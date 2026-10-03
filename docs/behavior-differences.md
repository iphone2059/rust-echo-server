# 与 C++ / Swift 服务端的差异

本移植以 `cpp-echo-server` 为行为基线（契约、协议、退出码、统计口径），结构上沿用 `swift-echo-server` 已经验收的模块划分与改进，并保持 `rust-echo-client` 的分层与惯用法。本文记录"哪些完全一致"和"哪些有意不同"，供三方对照评审。

## 与基线一致

- 参数契约：开关形式 `/x`、`-x`、`--x` 与 `=值`；名字与 `tcp`/`udp` 值按 ASCII 大小写不敏感；位置参数、空值、flag 带值、越界数值均为用法错误（退出码 1）；`/h` 不掩盖语法错误。取值范围、默认值、`/k` 仅 UDP、`/t` 仅 TCP、UDP 默认 `/rio-buffer` 65507 且显式值不得更小，全部一致。
- 数据面只有 RIO：源码策略脚本禁止 `WSASend`/`WSARecv`/`sendto`/`recvfrom`/`std::net::`/`TcpStream`/`UdpSocket`。
- TCP 接入：每个工作线程预投递 32 个 `AcceptEx`（上限 1024），地址缓冲区 `(SOCKADDR_STORAGE+16)*2` 字节；`SO_UPDATE_ACCEPT_CONTEXT` + `TCP_NODELAY` + 可选 `SO_SNDBUF`/`SO_RCVBUF`；按轮转把接受的 socket 交给固定工作线程，工作线程用同一 operation 地址回执。
- TCP 数据：每连接一个 RQ（1/1/1/1），每工作线程独占一个 CQ、一个 IOCP、一块注册内存（`slot_count × stride`）和一份索引最小堆；每连接两个完成槽的 CQ 容量；`/cq` 与 `/memory` 共同决定连接容量。
- UDP 数据：`/k` 深度的 `RIOReceiveEx` 常驻，收到即 `RIOSendEx` 原样回显再恢复接收；槽位步长 = `/rio-buffer` + 144 字节地址区；`深度 ≤ /cq ÷ 2`；停止先关 socket 取消请求，继续排空到 `outstanding == 0` 才释放注册内存。
- 通知与不变量：`RIONotify` 只接受 `ERROR_SUCCESS`；`RIO_CORRUPT_CQ`、通知迁移错误、必需的控制投递失败都以退出码 4 确定性终止，不重试、不轮询 CQ、无回退后端。
- 停止顺序：先关闭接入并 join 接入线程，再向工作线程发布 admission-closed 与 stop，全部 join 后释放；worker 退出需 phase ≥ admission-closed、活动连接 0、定时器堆空。
- 完成上下文在解引用前按分配范围、对齐与索引身份校验；`ERROR_NETNAME_DELETED` 视为连接级可恢复（预接受 RST），其余完成错误保持致命分类。
- 统计与退出码：`bytes` 只累计成功的 RIO 发送完成；UDP 的 receive/completion 含停止期间排空的终态完成；`MiB_per_sec` 用至少 1 ms 保护；端口冲突退出码 2；受控停止退出码 0；`/q` 不改变输出（服务端只在 `/stats` 输出）。

## 与 Swift 版本一致的有意差异（相对 C++ 基线）

1. **有界排空**：单次连续排空上限 64 个完成批次，排空内部同时观察 stop 与 `/w` 期限；饱和流量下受控停止仍有界。实测（本仓库进程套件）：满速 UDP 洪泛下 Ctrl+Break **605 ms**、TCP 回显突发下 **632 ms**，均以 `outstanding=0`/`active=0` 与空 stderr 结束。未取走的完成留在 CQ，由下一次通知取回。
2. **惰性通知**：只有在途请求存在时才武装 `RIONotify`（TCP 判据为活动连接数非零，UDP 为 `outstanding != 0`），投递即解除武装。空闲引擎不持有挂起注册，释放前无需合成 IOCP 包。
3. **接入路径不做第二次状态查询**：不调用 `WSAGetOverlappedResult`（`GetQueuedCompletionStatus` 的结果与 last-error 已足够）；worker 不调用 `getpeername`；不加载 `GetAcceptExSockaddrs`（AcceptEx 输出缓冲区仍按 API 要求分配但不解析，echo 服务不消费对端地址）。
4. **逐工作线程统计只在线程确实创建过时输出**；启动失败路径不会为从未启动的 worker 打印。
5. **容量检查在协调器**完成（`worker registered arena capacity`，退出码 2），因此容量不足时不会创建任何工作线程。

## 本移植特有的差异

1. **UDP `WSAECONNRESET` 后恢复槽位的完整接收容量**。C++ 与 Swift 在该分支只把操作改回 receive，保留失败操作留下的 `Length`；若失败的是发送，下一条较大的数据报可能被静默截断。Rust 版本把 `Length` 复位为 `/rio-buffer`（`udp::UdpEngine::on_completion`），单元测试固定该行为。
2. **停止后显式释放**：worker 关闭 CQ、解除注册、释放 arena 页（`worker::TcpWorker::destroy`、`arena::Arena::destroy`、`udp_runtime` 收尾），顺序与基线一致；`Drop` 只作为半初始化路径的兜底。
3. **命令行解码**：`std::env::args_os` + 有损转换，无法解码的参数按普通 token 处理，绝不因解码失败 panic（对应基线的 `wmain`/宽 `argv`）。
4. **原生错误在调用点捕获**（`GetLastError`/`WSAGetLastError`），不在稍后读取；阶段名沿用基线（`CreateEvent(worker ready)`、`worker registered arena size` 等）。
5. **所有权与线程模型**：worker 与 acceptor 使用 `std::thread`；可跨线程传递的原生句柄包在 `native::SendHandle`；接受操作表的 socket 字段用原子交换完成所有权转移；RIO 请求上下文是指向固定 `Box<[T]>` 首字段的地址，完成时按范围/对齐/索引校验后映射回槽位。
6. **unsafe 的边界**：`unsafe` 只出现在 FFI 边界（`native`、`rio`、`arena`、`endpoint`、`worker`、`tcp`、`udp_runtime`）与线程发送包装上；契约、连接状态机、引擎、接受策略、UDP 槽位机、定时器堆都是安全且可单测的纯逻辑。
7. 不实现客户端，也不依赖相邻工程（源码策略脚本检查 `rust-echo-client`/`cec::` 依赖与跨工程引用）。

## 验证覆盖

| 脚本 | 内容 |
|---|---|
| `tests/ces_source_policy.ps1` | 数据面仅 RIO、库代码不 panic（`unwrap`/`expect`/`panic!` 仅测试豁免）、无跨工程依赖 |
| `tests/ces_process_tests.ps1` | 12 项：命令行契约（含宽字符 token）、TCP 回显+统计+干净退出、`/t` 空闲超时、连接风暴、UDP 0/1/65507、UDP 满载排空、静默模式、端口冲突退出码 2、Ctrl+Break 排空、UDP 洪泛受控停止、TCP 突发受控停止 |
| `tests/ces_reset_storm_tests.ps1` | 400 次预接受 RST（`ERROR_NETNAME_DELETED`）后监听仍存活并正常回显 |
| `tests/ces_interop_tests.ps1` | 与 `cpp-echo-client` 的 5 个互操作场景（默认载荷、16 会话、32 MiB 单包、UDP 1 KiB、UDP 65507） |

单元测试 46 项覆盖契约、定时器堆（含 2 万步固定种子参考模型）、连接状态机、工作线程引擎、接受策略、UDP 槽位机、统计与生命周期谓词。
