//! Registered arena: one VirtualAlloc region per worker (TCP) or one for the whole UDP
//! engine, registered with RIO and sliced into fixed-stride slots.
//!
//! Every slot addresses a RIO_BUF inside the registration: a TCP slot is one
//! /rio-buffer-sized connection buffer, a UDP slot is one buffer plus the remote-address
//! area RIOReceiveEx writes the sender into.

use core::ffi::c_void;

use windows::Win32::memoryapi::{VirtualAlloc, VirtualFree};
use windows::Win32::mswsockdef::RIO_BUF;

use crate::native::{NativeError, RioFunctions};
use crate::rio::RegisteredBuffer;

// VirtualAlloc/VirtualFree flag values from winnt.h. The generated tree does not expose
// them under memoryapi, and the API takes plain u32 flags.
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;
const PAGE_READWRITE: u32 = 0x04;

/// Byte offset of a slot, rejecting index/stride combinations that would overflow or fall
/// outside the arena. This is the check behind every RIO_BUF the engine builds.
pub fn slot_offset(index: u32, stride: u32, total: usize) -> Option<usize> {
    if stride == 0 {
        return None;
    }
    let offset = (index as usize).checked_mul(stride as usize)?;
    if offset >= total {
        return None;
    }
    Some(offset)
}

/// Stride of a TCP connection slot: the whole registered buffer belongs to one echo.
pub fn tcp_stride(rio_buffer_bytes: u32) -> u32 {
    rio_buffer_bytes
}

/// Stride of a UDP slot: the datagram buffer plus the address area the completion writes.
pub fn udp_stride(rio_buffer_bytes: u32, address_bytes: usize) -> Option<u32> {
    (rio_buffer_bytes as usize).checked_add(address_bytes).and_then(|value| u32::try_from(value).ok())
}

/// Releases the pages and reports whether Windows accepted the release. Every Win32 result
/// is inspected: a silent failure here would leak the arena.
fn release_pages(base: *mut u8) -> bool {
    unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) }.as_bool()
}

/// A registered block of memory. The registration is process-scoped and stays alive for
/// the lifetime of the engine; dropping releases the pages, so callers must have stopped
/// posting operations first.
pub struct Arena {
    base: *mut u8,
    bytes: usize,
    registered: RegisteredBuffer,
}

impl Arena {
    pub fn create(rio: &RioFunctions, bytes: usize) -> Result<Self, NativeError> {
        if bytes == 0 {
            return Err(NativeError { stage: "arena size", code: 13 });
        }
        let base = unsafe { VirtualAlloc(None, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) } as *mut u8;
        if base.is_null() {
            return Err(NativeError { stage: "VirtualAlloc(arena)", code: 8 });
        }
        let slice = unsafe { core::slice::from_raw_parts_mut(base, bytes) };
        let registered = match RegisteredBuffer::register(rio, slice) {
            Ok(buffer) => buffer,
            Err(error) => {
                // The pages must not leak when registration is refused.
                debug_assert!(release_pages(base), "VirtualFree(arena) failed while aborting");
                return Err(error);
            }
        };
        Ok(Self { base, bytes, registered })
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn raw(&self) -> *mut u8 {
        self.base
    }

    pub fn registration(&self) -> windows::Win32::mswsockdef::RIO_BUFFERID {
        self.registered.raw()
    }

    /// Borrows a bounded window of the arena. The bounds are re-checked here so no caller
    /// can widen a view by accident.
    pub fn window(&mut self, offset: u32, length: u32) -> Result<&mut [u8], NativeError> {
        let start = offset as usize;
        let len = length as usize;
        if len == 0 || start > self.bytes || len > self.bytes - start {
            return Err(NativeError { stage: "arena window bounds", code: 13 });
        }
        Ok(unsafe { core::slice::from_raw_parts_mut(self.base.add(start), len) })
    }

    /// A RIO descriptor for a region, checked against the arena size and the registration.
    pub fn view(&self, offset: u32, length: u32) -> Result<RIO_BUF, NativeError> {
        if offset as usize >= self.bytes {
            return Err(NativeError { stage: "arena view offset", code: 13 });
        }
        self.registered.slice(offset, length)
    }

    /// A RIO descriptor for one fixed-stride slot.
    pub fn slot_view(&self, index: u32, stride: u32) -> Result<RIO_BUF, NativeError> {
        let offset = slot_offset(index, stride, self.bytes)
            .ok_or(NativeError { stage: "arena slot offset", code: 13 })?;
        self.registered.slice(offset as u32, stride)
    }

    /// A RIO descriptor for the tail of a slot, used for the UDP remote-address area.
    pub fn slot_tail_view(&self, index: u32, stride: u32, tail_offset: u32, tail_length: u32)
        -> Result<RIO_BUF, NativeError>
    {
        let offset = slot_offset(index, stride, self.bytes)
            .ok_or(NativeError { stage: "arena slot offset", code: 13 })?;
        if tail_offset as usize > stride as usize || tail_length as usize > stride as usize - tail_offset as usize {
            return Err(NativeError { stage: "arena slot tail bounds", code: 13 });
        }
        let start = offset + tail_offset as usize;
        self.registered.slice(start as u32, tail_length)
    }
}

impl Arena {
    /// Releases the region the way both baselines do: deregister with RIO first, then free
    /// the pages. The engine calls this once every posted request has completed and the
    /// owning threads have joined.
    pub fn destroy(&mut self, rio: &RioFunctions) {
        self.registered.deregister(rio);
        self.release_pages();
    }

    fn release_pages(&mut self) {
        if !self.base.is_null() {
            debug_assert!(release_pages(self.base), "VirtualFree(arena) failed during teardown");
            self.base = core::ptr::null_mut();
            self.bytes = 0;
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // Fallback for a partially initialised engine that never reached its explicit
        // tear-down; the registration is process-scoped in that case.
        self.release_pages();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_arithmetic_is_checked() {
        assert_eq!(slot_offset(0, 1_024, 4_096), Some(0));
        assert_eq!(slot_offset(3, 1_024, 4_096), Some(3_072));
        // A slot that starts at or beyond the end of the arena is rejected.
        assert_eq!(slot_offset(4, 1_024, 4_096), None);
        assert_eq!(slot_offset(1, 0, 4_096), None);
        assert_eq!(slot_offset(u32::MAX, 2, 4_096), None);
    }

    #[test]
    fn strides_match_the_baseline_layout() {
        assert_eq!(tcp_stride(16_384), 16_384);
        assert_eq!(udp_stride(65_507, 144), Some(65_651));
        assert_eq!(udp_stride(u32::MAX, 144), None);
        // The UDP arena holds depth x (payload + address area) bytes.
        assert_eq!(
            crate::contract::checked_arena_bytes(256, 65_651, u64::MAX),
            Some(16_806_656)
        );
    }
}


