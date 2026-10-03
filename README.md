# rust-echo-server

Rust 重写的 Windows x64 RIO Echo 服务端。参数、退出码、统计字段与收发路径沿用 `cpp-echo-server`，结构沿用 `swift-echo-server` 的既有验收结论：数据面只有注册 I/O（RIO），RIO 完成队列通过 IOCP 通知工作线程，不存在普通 `send`/`recv`、数据面轮询或其他回退后端。

## 架构

- **TCP 接入**：每个工作线程预投递 32 个 `AcceptEx`（总数上限 1024），完成由接入 IOCP 回收；已连接的 RIO socket 按轮转交给固定工作线程，工作线程用同一 operation 地址回执握手。
- **TCP 数据**：每连接一个 RIO RQ；每个工作线程独占一个 RIO CQ、一个 IOCP、一块预注册内存和一份索引最小堆。收到多少字节就回显多少字节，部分发送按偏移续发。
- **UDP 数据**：预投递固定深度的 `RIOReceiveEx`，完成后用 `RIOSendEx` 回显再恢复接收。
- **CQ 唤醒**：IOCP 只表示"RIO CQ 可读"；线程批量 `RIODequeueCompletion` 排空后按需 `RIONotify`。通知是惰性的：只有在途请求存在时才登记，空闲工作线程不持有挂起的注册。
- **生命周期**：接入只在全部 TCP 工作线程完成 IOCP/CQ/arena/定时器初始化后开放；停止时先关闭接入并 join 接入线程，再发布 admission-closed 屏障与 stop，全部 join 后按 CQ → 注册 → arena → socket → 端口 的顺序释放。UDP 先关 socket 取消请求，排空到 `outstanding == 0` 才释放注册内存。
- **不变量**：`RIONotify` 只接受 `ERROR_SUCCESS`；`RIO_CORRUPT_CQ`、通知迁移错误和必需的控制投递失败属于内部不变量损坏，进程以退出码 4 确定性终止，不重试、不轮询 CQ、不切换后端。

## 构建与运行

要求 Windows 10 或更新版本、支持 RIO 的网卡/协议栈、Rust 1.99 工具链与 MSVC x64 链接器、PowerShell 7。无第三方依赖（仅 windows-rs），不依赖相邻工程。

```powershell
cargo build --release
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
| `/w` | 默认不设时限；指定后到期受控停止 |
| `/b` | 0（系统默认）；`SO_SNDBUF`/`SO_RCVBUF`，0..2147483647 |
| `/k` | UDP 并发深度 256；1..65536；仅 UDP |
| `/threads` | 0 表示 min(max(CPU,1),32)；1..64 |
| `/rio-buffer` | TCP 每槽 16384 字节；UDP 省略时取 65507，显式值不得小于 65507；512..1048576 |
| `/cq` | 每 CQ 容量 4096；64..1048576（TCP 每连接至少两个完成槽，UDP 至少深度两倍） |
| `/memory` | 注册内存上限 1073741824；≥1048576，按工作线程均分 |
| `/q` | 接受但不改变输出；服务端仅在 `/stats` 时输出 |
| `/stats` | 输出逐工作线程记录与 `final` 汇总 |
| `/h`、`/help` | 打印用法并退出 0；语法与范围错误仍返回 1，不会被 `/h` 掩盖 |

开关接受 `/x`、`-x`、`--x` 与 `=值` 形式；开关名和 `tcp`/`udp` 值按 ASCII 大小写不敏感比较。

退出码：0 成功（含受控停止），1 参数错误，2 网络准备失败（bind、RIO/IOCP/容量），3 未使用，4 内部错误。`Ctrl+C`/`Ctrl+Break` 触发受控停止并退出 0。

`/stats` 汇总示例：

```
[worker 0] accepted=938 completions=938 receives=938 sends=0 bytes=0 active=0
final protocol=tcp elapsed_ms=2141 accepted=3750 completions=3750 receives=3750 sends=0 bytes=0 MiB_per_sec=0.00 active=0
```

## 测试与验证

```powershell
cargo test                                                                    # 46 项单元测试
pwsh -NoProfile -File tests/ces_source_policy.ps1   -ProjectRoot .            # 数据面/无 panic/无跨工程依赖
pwsh -NoProfile -File tests/ces_process_tests.ps1   -ServerPath target/debug/rust-echo-server.exe
pwsh -NoProfile -File tests/ces_reset_storm_tests.ps1 -ServerPath target/debug/rust-echo-server.exe
pwsh -NoProfile -File tests/ces_interop_tests.ps1   -ServerPath target/debug/rust-echo-server.exe -ClientPath ../cpp-echo-client/build/release/cpp-echo-client.exe
```

进程套件包含 12 个场景：命令行契约（含宽字符 token）、TCP 回显与统计、`/t` 空闲超时、连接风暴下停止、UDP 0/1/65507 字节、UDP 满载排空、静默模式、端口冲突退出码 2、Ctrl+Break 排空、UDP 洪泛受控停止（实测 605 ms）、TCP 突发受控停止（实测 632 ms）。互操作套件用 `cpp-echo-client` 逐字节校验回显并核对服务端 `bytes`。

## 实现

核心位于 `src/`，`main.rs` 只做控制台注册、参数解析与退出码：

| 模块 | 职责 |
|---|---|
| `types`、`contract` | 词汇表、选项、生命周期谓词、统计格式化；参数解析与校验算术、通知迁移 |
| `connection`、`engine` | TCP 回显状态机与每工作线程引擎（槽位、定时器、统计、生命周期） |
| `acceptor` | AcceptEx 操作表策略（状态机）+ 与工作线程共享的原子 socket 表 |
| `udp` | UDP 槽位机（接收→回显→恢复、`WSAECONNRESET`、排空与释放前置条件） |
| `timer` | 固定容量索引最小堆（deadline, index 排序，等待值饱和） |
| `native`、`rio`、`arena`、`endpoint` | Winsock/RIO/AcceptEx 绑定与所有者、IOCP 数据包、注册内存、端点与 AcceptEx 上下文 |
| `worker`、`tcp`、`udp_runtime`、`server` | 工作线程循环与交接、TCP 协调器与接入线程、UDP 引擎循环、Winsock/RIO 装载与协议分发 |

详见 [与 C++ / Swift 服务端的差异](docs/behavior-differences.md)（一致性清单、有意保留的差异、本移植特有差异、验证覆盖）。
