# 与当前 C++ 服务端的对照

行为与架构参考 `cpp-echo-server` 提交 `b1059f27b91bd649e7161a9a7ff5d4de72d847af`。Rust 保留安全状态机与 RAII 所有权，不依赖相邻语言工程。

## 对齐的契约与运行路径

- CLI 接受 `/x`、`-x`、`--x` 与 `=值`，只对 ASCII 大小写作不敏感比较，数值只接受 ASCII 十进制数字。`/w 0` 不限时，`/threads 0` 自动选择最多 64 个 TCP 工作线程；UDP 只接受 `/threads 0` 或 `1`，并归一为单工作线程。`/t` 仅 TCP、`/k` 仅 UDP。宽参数按消费顺序校验 UTF-16，`/h` 不掩盖先前语法、容量或协议错误。
- TCP 每工作线程独占 CQ、IOCP、注册 arena、槽位表与固定容量索引最小堆。容量由 `/cq ÷ 2` 与逐工作线程的系统页预算共同决定，余页分给前面的工作线程；每连接一个 RQ，收到多少字节就回显多少字节，部分发送按偏移续发，空闲期限随成功投递更新。
- TCP 按逐工作线程预算检查、资源初始化、启动、等待 ready 的顺序推进，全部就绪后才创建接入资源并开放交接。启动失败也停止并 join 已启动线程，随后写诊断；`/stats` 仅输出一条 `final`，其中 `workers` 是实际启动数。
- TCP 接入窗口为 `max(8, min(2 × workers, 128))`。AcceptEx 完成后设置接受上下文、socket 选项并校验 `GetAcceptExSockaddrs` 输出。轮转扫描有可预留 admission credit 的工作线程；信用覆盖活动连接与交接中的连接，只有所有工作线程满时增加 `rejected`。信用在交接拒收、RQ 创建失败或连接最终释放时归还。
- `ERROR_NETNAME_DELETED`、`WSAECONNRESET`、`WSAECONNABORTED` 是连接级预接受错误。同步重投最多连续尝试四次，之后进入 deferred 状态并向接入 IOCP 投递重投包；停止必须消费 deferred 包以及已发布的完成和交接回执。
- UDP 单工作线程，固定 `/k` 深度，槽位步长为 `/rio-buffer + 144`。默认最大 IPv4 UDP 载荷 65507，显式 buffer 不得更小，CQ 至少深度两倍；包括零字节在内的数据报按原长度回显。`WSAECONNRESET` 后恢复完整接收容量，当前 C++ 已采用相同恢复规则。
- UDP 通过容量检查后的初始化失败也进入最终统计和诊断路径；socket、绑定与 RIO 注册/CQ/RQ 失败按 C++ 计入 `network_errors`，纯内存或 IOCP 分配失败不增加该计数。半初始化资源由 RAII 回收，容量错误退出 1。
- CQ 通知仅在原生请求在途且尚未 armed 时登记。通知身份同时校验 completion key 与 OVERLAPPED，真实投递消费 armed 状态，每次排空最多 64 个批次。`WSAEALREADY` 是重复武装错误；CQ 损坏、身份错误与必需控制包投递失败退出 4，没有轮询或回退后端。
- 停止顺序为关闭接入、join acceptor、发布 admission-closed 与 stop、工作线程关闭连接并排空、join workers。释放前验证活动连接、定时器、RIO outstanding 为零、所有槽位与信用完整归还。UDP 先关闭 socket，再排空所有已发布请求。最后一条真实通知可仍在途；OVERLAPPED 与 key 保留到 IOCP 关闭，禁止合成通知包。
- 统计按原生完成计数。成功 receive/send 完成分别累积 `received_bytes`/`sent_bytes`，`bytes` 累积成功发送；失败完成只在尚未 closing 时增加 `network_errors`，成功的终态完成仍计入流量。接入错误与全部工作线程统计合并后输出。受控停止退出 0、参数错误退出 1、网络准备或运行错误退出 2、内部不变量损坏退出 4。
- `CES_DIAG_FILE` 可选诊断在所有 TCP 工作线程 join 后写入，各行字段与 C++ 一致；UDP 排空和释放后写入 worker 0。诊断写入失败不改变退出码或标准输出。debug 构建检查通知无饥饿、登记数与投递数之差最多为 1。

## Rust 保留的实现方式

- 工作线程、CQ 和单次 `VirtualAlloc` arena 分配模式与 C++ 相同，但 Rust 为每个 TCP 连接槽或 UDP 槽独立注册 `BufferId`，RIO 描述符使用槽内偏移。微软 [RIOSend 文档](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_riosend)要求发送期间整段注册不能用于并行收发；当前 C++ 多槽共用一个注册的方式存在违反该约束的潜在缺陷，Rust 不复制这一行为。arena 字节数、页预算和 CQ 容量保持原有计算，注册失败先解除已成功的槽注册，再释放页面。
- `server.rs` 是 Winsock/RIO 装载与协议分发入口，`engine.rs` 是无原生句柄的 TCP 状态机，两者职责不同。实际线程、TCP 接入与 UDP 循环位于 `internal.rs`，由库的历史模块路径重导出。
- 采用 `std::thread`、`Arc` 与原子信用；接受 socket 通过原子交换转移所有权。跨线程固定接受表的 Win32 输出区使用 `UnsafeCell`，immutable 索引和身份字段保持独立；RIO 请求地址在解引用前校验范围、对齐与索引。
- 原生错误在调用点分别通过 `GetLastError` 或 `WSAGetLastError` 捕获。`RIO_INVALID_BUFFERID` 使用 Windows x64 的 `0x00000000FFFFFFFF` sentinel，不能当作合法注册。
- CQ 和注册所有者保存 RIO 函数表并在 `Drop` 中清理半初始化路径；arena 总是先解除注册再释放页面。显式收尾仍按 CQ → 注册 → arena → socket → port 执行。出现仍有在途请求的异常析构时以内部错误终止，避免释放原生 I/O 引用中的内存。
- Rust 在连续排空批次之间也观察受控停止；UDP 同时观察 `/w` 到期。这样保留当前 C++ 的有界排空结构，并缩短饱和流量下的取消响应。
- 帮助文本中的程序名为 `rust-echo-server`；原生准备失败的具体阶段标签可能随 Rust 所有者划分不同，退出分类保持一致。

## 验证覆盖

Rust 单元测试覆盖 CLI 数值与 UTF-16 优先级、页预算、接受窗口、跨线程信用预留、deferred 接入停止、部分发送、关闭取消统计、UDP 零长度与 reset 恢复、定时器参考模型、RIO sentinel/ABI、CQ 与注册的单次析构，以及通知快照不变量。

现有 PowerShell 进程套件覆盖 TCP/UDP 回显、空闲超时、统计与受控停止，reset storm 覆盖预接受 RST，互操作套件使用 C++ 客户端逐字节核验载荷与服务端字节总数。本次源码修改后的验证结果由统一编译测试阶段报告。
