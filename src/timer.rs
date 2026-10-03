//! Worker-private index minimum heap over connection deadlines.
//!
//! Only the owning thread touches it, so no synchronisation is needed. The heap keeps a
//! position map so a connection's deadline can be updated or removed in place, and its
//! capacity is fixed for the whole run: it never grows past the worker's slot count.
//!
//! This is the same structure as ces_timer_heap in the C++ baseline and CESTimerHeap in
//! the Swift port, including the order rule (deadline, then index) and the wait rule
//! (INFINITE when empty, saturated one below INFINITE otherwise).

use crate::types::{TimerNode, INFINITE};

#[derive(Debug)]
pub struct TimerHeap {
    capacity: usize,
    size: usize,
    nodes: Vec<TimerNode>,
    /// Position of a connection inside `nodes`, or -1 when it has no deadline.
    positions: Vec<i32>,
}

impl TimerHeap {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            size: 0,
            nodes: vec![TimerNode::default(); capacity],
            positions: vec![-1; capacity],
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn contains(&self, connection_index: u32) -> bool {
        (connection_index as usize) < self.capacity && self.positions[connection_index as usize] >= 0
    }

    pub fn next_deadline(&self) -> Option<u64> {
        if self.size == 0 { None } else { Some(self.nodes[0].deadline) }
    }

    /// Position of a connection inside the heap, as the reference model reads it.
    pub fn position_of(&self, connection_index: u32) -> Option<usize> {
        if (connection_index as usize) >= self.capacity {
            return None;
        }
        let position = self.positions[connection_index as usize];
        if position < 0 { None } else { Some(position as usize) }
    }

    fn less(&self, a: usize, b: usize) -> bool {
        let left = self.nodes[a];
        let right = self.nodes[b];
        (left.deadline, left.connection_index) < (right.deadline, right.connection_index)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.nodes.swap(a, b);
        let left = self.nodes[a].connection_index as usize;
        let right = self.nodes[b].connection_index as usize;
        self.positions[left] = a as i32;
        self.positions[right] = b as i32;
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if !self.less(index, parent) {
                break;
            }
            self.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        loop {
            let left = index * 2 + 1;
            if left >= self.size {
                break;
            }
            let right = left + 1;
            let smallest = if right < self.size && self.less(right, left) { right } else { left };
            if !self.less(smallest, index) {
                break;
            }
            self.swap(index, smallest);
            index = smallest;
        }
    }

    /// Schedules or reschedules a connection. Returns false when the index is outside the
    /// fixed capacity or the heap is full: the caller must treat that as a hard failure
    /// instead of silently dropping a deadline.
    pub fn insert_or_update(&mut self, deadline: u64, connection_index: u32) -> bool {
        let slot = connection_index as usize;
        if slot >= self.capacity {
            return false;
        }
        let existing = self.positions[slot];
        if existing >= 0 {
            let position = existing as usize;
            let previous = self.nodes[position].deadline;
            if deadline == previous {
                return true;
            }
            self.nodes[position].deadline = deadline;
            if deadline < previous {
                self.sift_up(position);
            } else {
                self.sift_down(position);
            }
            return true;
        }
        if self.size == self.capacity {
            return false;
        }
        let position = self.size;
        self.size += 1;
        self.nodes[position] = TimerNode { deadline, connection_index };
        self.positions[slot] = position as i32;
        self.sift_up(position);
        true
    }

    /// Drops a connection's deadline. Removing an unscheduled connection is not an error.
    pub fn remove(&mut self, connection_index: u32) -> bool {
        let slot = connection_index as usize;
        if slot >= self.capacity {
            return false;
        }
        let position = self.positions[slot];
        if position < 0 {
            return false;
        }
        let position = position as usize;
        self.positions[slot] = -1;
        let last = self.size - 1;
        self.size = last;
        if position != last {
            self.nodes[position] = self.nodes[last];
            self.positions[self.nodes[position].connection_index as usize] = position as i32;
            let parent = if position > 0 { Some((position - 1) / 2) } else { None };
            if let Some(parent) = parent {
                if self.less(position, parent) {
                    self.sift_up(position);
                    return true;
                }
            }
            self.sift_down(position);
        }
        true
    }

    /// Wakes up only the connections whose deadline has passed. Each removed connection is
    /// reported so the caller can close it.
    pub fn pop_expired(&mut self, now: u64, out: &mut Vec<u32>) -> usize {
        let mut count = 0;
        while self.size > 0 && self.nodes[0].deadline <= now {
            let node = self.nodes[0];
            self.remove(node.connection_index);
            out.push(node.connection_index);
            count += 1;
        }
        count
    }

    /// Milliseconds to wait for the nearest deadline: INFINITE when nothing is scheduled,
    /// zero when the nearest deadline has already passed, and otherwise one below INFINITE
    /// at most so the value is always a usable timeout.
    pub fn wait_milliseconds(&self, now: u64) -> u32 {
        let Some(deadline) = self.next_deadline() else {
            return INFINITE;
        };
        if deadline <= now {
            return 0;
        }
        let remaining = deadline - now;
        remaining.min(u64::from(INFINITE) - 1) as u32
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WAIT_TIMEOUT;

    fn xorshift(state: &mut u32) -> u32 {
        let mut value = *state;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        *state = value;
        value
    }

    #[test]
    fn orders_by_deadline_then_index() {
        let mut heap = TimerHeap::new(8);
        assert!(heap.insert_or_update(30, 2));
        assert!(heap.insert_or_update(10, 1));
        assert!(heap.insert_or_update(20, 0));
        assert_eq!(heap.next_deadline(), Some(10));
        let mut expired = Vec::new();
        assert_eq!(heap.pop_expired(25, &mut expired), 2);
        assert_eq!(expired, vec![1, 0]);
        assert_eq!(heap.next_deadline(), Some(30));
        assert_eq!(heap.len(), 1);
        // Equal deadlines are ordered by connection index.
        let mut tied = TimerHeap::new(4);
        assert!(tied.insert_or_update(50, 3));
        assert!(tied.insert_or_update(50, 1));
        let mut expired = Vec::new();
        // Both deadlines passed at once; the pop order is by index.
        assert_eq!(tied.pop_expired(50, &mut expired), 2);
        assert_eq!(expired, vec![1, 3]);
        // Nothing else was due before the deadline.
        let mut early = TimerHeap::new(2);
        assert!(early.insert_or_update(50, 0));
        assert!(early.insert_or_update(50, 1));
        let mut expired = Vec::new();
        assert_eq!(early.pop_expired(49, &mut expired), 0);
        assert!(expired.is_empty());
    }

    #[test]
    fn update_moves_the_entry_in_both_directions() {
        let mut heap = TimerHeap::new(4);
        assert!(heap.insert_or_update(100, 0));
        assert!(heap.insert_or_update(200, 1));
        assert!(heap.insert_or_update(5, 0));
        assert_eq!(heap.next_deadline(), Some(5));
        assert_eq!(heap.len(), 2);
        assert!(heap.insert_or_update(500, 0));
        assert_eq!(heap.next_deadline(), Some(200));
        assert!(heap.contains(0));
        // Re-scheduling the same deadline keeps the entry where it is.
        assert!(heap.insert_or_update(500, 0));
        assert_eq!(heap.next_deadline(), Some(200));
    }

    #[test]
    fn remove_reports_missing_entries_and_repairs_the_heap() {
        let mut heap = TimerHeap::new(4);
        assert!(!heap.remove(0));
        assert!(heap.insert_or_update(10, 0));
        assert!(heap.insert_or_update(20, 1));
        assert!(heap.insert_or_update(30, 2));
        assert!(heap.remove(0));
        assert!(!heap.contains(0));
        assert_eq!(heap.next_deadline(), Some(20));
        assert_eq!(heap.len(), 2);
        assert!(heap.remove(2));
        assert_eq!(heap.next_deadline(), Some(20));
    }

    #[test]
    fn capacity_is_fixed_and_indices_are_bounds_checked() {
        let mut heap = TimerHeap::new(2);
        assert!(heap.insert_or_update(1, 0));
        assert!(heap.insert_or_update(2, 1));
        // Full: a third distinct connection is refused instead of growing the heap.
        assert!(!heap.insert_or_update(3, 2));
        // Out-of-range indices are refused even when a slot is free.
        assert!(!heap.insert_or_update(3, 99));
        assert!(!heap.remove(99));
        assert_eq!(heap.len(), 2);
    }

    #[test]
    fn wait_is_infinite_when_empty_and_saturates_below_infinite() {
        let mut heap = TimerHeap::new(2);
        assert_eq!(heap.wait_milliseconds(10), INFINITE);
        assert!(heap.insert_or_update(20, 0));
        assert_eq!(heap.wait_milliseconds(10), 10);
        assert_eq!(heap.wait_milliseconds(20), 0);
        assert_eq!(heap.wait_milliseconds(25), 0);
        assert!(heap.insert_or_update(u64::MAX, 0));
        assert_eq!(heap.wait_milliseconds(0), INFINITE - 1);
        assert_ne!(heap.wait_milliseconds(0), WAIT_TIMEOUT + 1);
    }

    #[test]
    fn heap_matches_a_fixed_seed_reference_model() {
        const CAPACITY: u32 = 64;
        const STEPS: u32 = 20_000;
        let mut heap = TimerHeap::new(CAPACITY as usize);
        let mut active = vec![false; CAPACITY as usize];
        let mut deadlines = vec![0u64; CAPACITY as usize];
        let mut state = 0x51A7_E123u32;
        for step in 0..STEPS {
            let operation = xorshift(&mut state) & 3;
            let index = xorshift(&mut state) % CAPACITY;
            let now = u64::from(step % 4096);
            match operation {
                0 | 1 => {
                    let deadline = u64::from(xorshift(&mut state) % 4096);
                    assert!(heap.insert_or_update(deadline, index));
                    active[index as usize] = true;
                    deadlines[index as usize] = deadline;
                }
                2 => {
                    let expected = active[index as usize];
                    assert_eq!(heap.remove(index), expected);
                    active[index as usize] = false;
                }
                _ => {
                    // pop_expired drains every deadline that has passed, ordered by
                    // (deadline, index): the reference model builds that list directly.
                    let mut expected: Vec<u32> = (0..CAPACITY)
                        .filter(|candidate| {
                            active[*candidate as usize] && deadlines[*candidate as usize] <= now
                        })
                        .collect();
                    expected.sort_by_key(|candidate| (deadlines[*candidate as usize], *candidate));
                    let mut expired = Vec::new();
                    let count = heap.pop_expired(now, &mut expired);
                    assert_eq!(count, expected.len());
                    assert_eq!(expired, expected);
                    for index in &expected {
                        active[*index as usize] = false;
                    }
                }
            }

            // The heap root, the position map and the size must agree with the model.
            let mut minimum: Option<u32> = None;
            let mut active_count = 0;
            for index in 0..CAPACITY {
                if !active[index as usize] {
                    assert!(!heap.contains(index));
                    continue;
                }
                active_count += 1;
                let position = heap.position_of(index).expect("scheduled connection has a position");
                assert!(position < heap.len());
                assert_eq!(heap.nodes[position].connection_index, index);
                assert_eq!(heap.nodes[position].deadline, deadlines[index as usize]);
                let better = match minimum {
                    None => true,
                    Some(current) => {
                        (deadlines[index as usize], index) < (deadlines[current as usize], current)
                    }
                };
                if better {
                    minimum = Some(index);
                }
            }
            assert_eq!(heap.len(), active_count);
            if let Some(index) = minimum {
                assert_eq!(heap.nodes[0].connection_index, index);
                assert_eq!(heap.nodes[0].deadline, deadlines[index as usize]);
            }
            let expected_wait = match minimum {
                None => INFINITE,
                Some(index) if deadlines[index as usize] <= now => 0,
                Some(index) => (deadlines[index as usize] - now).min(u64::from(INFINITE) - 1) as u32,
            };
            assert_eq!(heap.wait_milliseconds(now), expected_wait);
        }
    }
}
