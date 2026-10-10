# rust-echo-server

Rust 重写的 Windows x64 MSVC RIO Echo 服务端。参数、退出码、统计字段与收发路径对齐当前 `cpp-echo-server`：数据面只有注册 I/O（RIO），RIO 完成队列通过 IOCP 通知工作线程，不存在普通 `send`/`recv`、数据面轮询或其他回退后端。

## 架构

- **TCP 接入**：预投递 `max(8, min(2 × workers, 128))` 个 `AcceptEx`，完成由接入 IOCP 回收；按轮转扫描并原子预留有空位工作线程的 admission credit，交接期间也占用信用，全部工作线程满时才拒绝连接。工作线程用同一 operation 地址回执；预接受 reset 单独恢复，同步连续 reset 重试四次后通过 IOCP 延后重投。
- **TCP 数据**：每连接一个 RIO RQ；每个工作线程独占一个 RIO CQ、一个 IOCP、一次 `VirtualAlloc` arena 分配和一份索引最小堆。每个连接槽独立注册 `BufferId`，收到多少字节就回显多少字节，部分发送按槽内偏移续发。
- **UDP 数据**：预投递固定深度的 `RIOReceiveEx`，完成后用 `RIOSendEx` 回显再恢复接收。每槽独立注册载荷及地址区域，全部槽仍共用一次 arena 分配。
- **CQ 唤醒**：IOCP 只表示"RIO CQ 可读"；线程批量 `RIODequeueCompletion` 排空后按需 `RIONotify`。通知是惰性的：只有在途请求存在时才登记，空闲工作线程不持有挂起的注册。
- **生命周期**：逐个初始化、启动 TCP 工作线程并等待 ready，全部就绪后才创建并开放接入；部分初始化失败也停止、join 已启动线程并输出终结统计与诊断。停止时先关闭接入并 join 接入线程，再发布 admission-closed 屏障与 stop，工作线程排空后返回完整资源所有者；协调器 join 后按 CQ → 注册 → arena → socket → 端口 的顺序释放，全部 join 后汇总。UDP 先关 socket 取消请求，排空到 `outstanding == 0` 才释放注册内存；挂起通知保留真实身份直到端口关闭，不伪造通知。
- **不变量**：`RIONotify` 只接受 `ERROR_SUCCESS`；`RIO_CORRUPT_CQ`、通知迁移错误和必需的控制投递失败属于内部不变量损坏，进程以退出码 4 确定性终止，不重试、不轮询 CQ、不切换后端。

## 构建与运行

要求 Windows 10 或更新版本、支持 RIO 的网卡/协议栈、Rust 1.99 工具链与 MSVC x64 链接器、PowerShell 7。无第三方依赖（仅 windows-rs），不依赖相邻工程。
`windows` 依赖持续跟踪 `microsoft/windows-rs` 的默认 Git 分支，不固定 `rev`，仓库不保留 `Cargo.lock`；构建时按当时可用的依赖解析。

```powershell
.\build_release.ps1
.\target\release\rust-echo-server.exe /p tcp /s 7000 /threads 8 /cq 65536 /memory 2147483648 /stats
.\target\release\rust-echo-server.exe /p udp /s 7000 /k 4096 /cq 8192 /memory 1073741824 /stats
.\target\release\rust-echo-server.exe /h
```

## 参数与结果

| 参数 | 默认值 / 语义 |
|---|---|
| `/p tcp\|udp` | 必填；不接受位置参数 |
| `/s` | 端口 7；1..65535 |
| `/t` | TCP 空闲超时 300 秒；1..4294967295；仅 TCP |
| `/w` | 0（不设时限）；0..4294967295，非零值到期受控停止 |
| `/b` | 0（系统默认）；`SO_SNDBUF`/`SO_RCVBUF`，0..2147483647 |
| `/k` | UDP 并发深度 256；1..65536；仅 UDP |
| `/threads` | 0 表示 min(max(CPU,1),64)；0..64；UDP 仅接受 0 或 1 并始终使用单工作线程 |
| `/rio-buffer` | TCP 每槽 16384 字节；UDP 省略时取 65507，显式值不得小于 65507；512..1048576 |
| `/cq` | 每 CQ 容量 4096；64..1048576（TCP 每连接至少两个完成槽，UDP 至少深度两倍） |
| `/memory` | 注册内存上限 1073741824；≥1048576；TCP 按系统页均分，余页分给前面的工作线程 |
| `/q` | 接受但不改变输出；服务端仅在 `/stats` 时输出 |
| `/stats` | 输出一条 `final` 汇总 |
| `/h`、`/help` | 打印用法并退出 0；语法与范围错误仍返回 1，不会被 `/h` 掩盖 |

开关接受 `/x`、`-x`、`--x` 与 `=值` 形式；开关名和 `tcp`/`udp` 值按 ASCII 大小写不敏感比较。
数值仅接受 ASCII 十进制数字；无效 UTF-16 参数返回 `invalid-utf16`，保留参数消费顺序与错误优先级。

退出码：0 成功（含受控停止），1 参数错误，2 网络准备失败（bind、RIO/IOCP/容量），3 未使用，4 内部错误。`Ctrl+C`/`Ctrl+Break` 触发受控停止并退出 0。

`/stats` 的 `received_bytes`、`sent_bytes` 是成功原生完成的字节数，`bytes` 等于成功回显发送字节数；关闭后的取消完成不增加 `network_errors`。通知诊断可用 `CES_DIAG_FILE` 指定文件，全部工作线程 join 后写入通知登记、投递及饥饿计数，写入失败不改变退出码。

`/stats` 汇总示例：

```
final protocol=tcp elapsed_ms=2141 workers=4 accepted=3750 active=0 outstanding=0 completions=3750 receives=3750 sends=0 received_bytes=0 sent_bytes=0 bytes=0 network_errors=0 rejected=0 MiB_per_sec=0.00
```

## 测试与验证

完整门禁按格式化、Release、Debug 顺序运行；`-InteropClientPath` 可选，传入参考客户端时额外执行 TCP/UDP 互通验证：

```powershell
.\format.ps1
.\build_release.ps1 -InteropClientPath ..\cpp-echo-client\build\release\cpp-echo-client.exe
.\build_debug.ps1 -InteropClientPath ..\cpp-echo-client\build\release\cpp-echo-client.exe
```

构建脚本先删除生成的 `Cargo.lock` 并执行 `cargo update`，再运行源码策略、所选配置的编译及单元测试、进程套件和 reset storm；成功或失败退出时都清理 `Cargo.lock`。

单独运行已有检查：

```powershell
cargo test                                                                    # 状态机、契约与原生所有权测试
pwsh -NoProfile -File tests/ces_source_policy.ps1   -ProjectRoot .            # 数据面/无 panic/无跨工程依赖
pwsh -NoProfile -File tests/ces_process_tests.ps1   -ServerPath target/debug/rust-echo-server.exe
pwsh -NoProfile -File tests/ces_reset_storm_tests.ps1 -ServerPath target/debug/rust-echo-server.exe
pwsh -NoProfile -File tests/ces_interop_tests.ps1   -ServerPath target/debug/rust-echo-server.exe -ClientPath ../cpp-echo-client/build/release/cpp-echo-client.exe
```

进程套件包含命令行契约（含宽字符 token）、TCP 回显与统计、`/t` 空闲超时、连接风暴下停止、UDP 0/1/65507 字节、UDP 满载排空、静默模式、端口冲突退出码 2、Ctrl+Break 排空、UDP 洪泛受控停止和 TCP 突发受控停止。互操作套件用 `cpp-echo-client` 逐字节校验回显并核对服务端 `bytes`。

## 实现

核心位于 `src/`，`main.rs` 只做控制台注册、参数解析与退出码：

| 模块 | 职责 |
|---|---|
| `types`、`contract` | 词汇表、选项、生命周期谓词、统计格式化；参数解析与校验算术、通知迁移 |
| `internal::connection`、`engine` | TCP 回显状态机与无原生句柄的每工作线程引擎（槽位、定时器、统计、生命周期） |
| `internal::acceptor` | AcceptEx 操作表策略、admission credit 与原子 socket 交接 |
| `internal::udp`、`internal::udp::runtime` | UDP 槽位机与原生排空循环 |
| `internal::worker::timer` | 固定容量索引最小堆（deadline, index 排序，等待值饱和） |
| `native` 及其 `rio`、`arena`、`endpoint` 子模块 | Winsock/RIO/AcceptEx 绑定与所有者、IOCP 数据包、注册内存、端点与 AcceptEx 上下文 |
| `internal::worker`、`internal::worker::tcp`、`server` | 工作线程循环与交接、TCP 协调器与接入线程、Winsock/RIO 装载与协议分发 |

详见 [与当前 C++ 服务端的差异](docs/behavior-differences.md)（一致性清单、Rust 所有权边界与验证覆盖）。
