# Connection 字段与并发边界

本表对应当前 close/accept 重构工作区。TCP accept 线程只移交未发布的 Socket；
PROCESS/THREAD 的 `add_connection()`、就绪事件修改和物理关闭由 `fd % reactor_num` 对应的 reactor 执行。
BASE 在接收连接的 worker 自己的 reactor 中执行；PROCESS 的所属 reactor 位于 master 进程；THREAD 位于 event worker 线程。

判断是否需要 atomic，依据实际的读写双方及其同步方式，不能只看写入者是否唯一。
普通字段被另一个线程读取时，只有读取者加锁、写入者不加锁，并不能排除数据竞争。
跨进程共享内存也不能依赖 `volatile` 代替同步。

## 同一 session 内不变的字段：普通类型

这些字段在 `add_connection()` 中初始化，发布后不再改变；退役和 fd 复用会开启下一代 session。
它们不是进程生命周期内的静态字段。worker 要在槽位锁内重新验证 session 后，才能取得这一代的稳定值。

| 字段 | 初始化/用途 |
| --- | --- |
| `socket_type` | 监听端口的协议类型 |
| `fd` | 当前 socket 的系统 fd |
| `session_id` | 当前槽位的 session 代号 |
| `ssl` | 发布前已经创建的 TLS/DTLS 实例是否存在 |
| `reactor_id` | 所属 reactor，session 内不迁移 |
| `server_fd` | 对应监听 socket |
| `local_port` | 本地端口快照 |
| `local_addr_index` | 本地地址索引 |
| `info` | 对端地址快照 |
| `connect_time` | 建连时间 |

入口：`src/server/master.cc: Server::add_connection()`。
重用时仍然需要 `Connection::lock`；不能以字段在 session 内不变为由去掉 generation 校验。
未加锁的 `get_connection_verify*()` 属于乐观查找，不能当作对槽位生命周期的持有。

## 仅所属 reactor 修改和使用的字段：普通类型

| 字段 | 确切含义/读写路径 |
| --- | --- |
| `close_queued` | 输出队列已有关闭标记，`send_to_connection()` / 输出排空 |
| `close_reset` | 最终释放时发送 RST，关闭命令 / 物理关闭 |
| `close_abort` | 丢弃未发送输出，关闭命令或传输错误 / 输出路径 |
| `close_notification_started` | 关闭通知已经开始投递，`request_close()` |
| `close_waiting_worker` | 等待 worker 的 CLOSE 命令，关闭通知 / 写事件 |
| `close_worker_received` | CLOSE 命令已经到达所属 reactor |
| `recv_paused` | 应用暂停接收，PAUSE/RESUME 命令 |
| `recv_delayed` | 延迟接收尚未被显式解除 |
| `recv_throttled` | 输入积压暂时关闭 READ，背压定时器 |
| `recv_shutdown` | reactor 正在退出，不再接收新数据 |
| `high_watermark` | 所属输出队列已经越过高水位 |
| `http_upgrade` | 所属协议解析器已切换到 WebSocket |
| `waiting_time` | 背压重试间隔 |
| `timer` | 背压定时器，创建、取消、触发均在所属 reactor |
| `websocket_buffer` | 所属协议解析器保存的分片缓存 |
| `object` | 所属协议解析器的 HTTP/Redis 请求对象 |

worker 对 RST/丢弃输出的要求通过 CLOSE 命令的 `ext_flags` 传递，不直接写
`close_reset` 或 `close_abort`。这里既不需要 atomic，也不需要给每次 recv 增加槽位锁。

## 由槽位锁协调的普通字段

| 字段 | 参与者和保护方式 |
| --- | --- |
| `close_actively` | worker 在关闭认领阶段写入，同一锁内确定 onClose 参数 |
| `close_callback_state` | worker 在锁内认领/完成一次原生 onClose 分发 |
| `connect_callback_claimed` | worker 在锁内认领一次 CONNECT 分发 |
| `close_worker_started` | worker 在锁内记录关闭处理已开始；PROCESS 接收事件在同一锁内检查 |
| `close_worker_claimed` | worker 在锁内认领关闭命令，投递失败才释放认领 |
| `session_released` | reactor 在锁内退役；其他 worker 在锁内读取，所属 reactor 可直接读取 |
| `ssl_client_cert` | worker 在锁内安装/摘除自己的证书对象；快照读取持有同一锁 |
| `ssl_client_cert_pid` | 与证书指针在同一锁内访问，禁止其他进程解引用私有证书内存 |
| `protect` | worker 的 protect API、后台心跳快照与所属 reactor 的空闲判定共用槽位锁；reactor 判定超时后在解锁前发布 close_reason |

这些字段无需再各自增加 atomic。锁内完成认领后必须释放锁，再调用 PHP、取消协程或发 IPC。
槽位锁不能跨越用户回调；回调返回后需要再次验证 session。

## 需要原子访问的字段

| 字段 | 实际竞争 | 选择 |
| --- | --- | --- |
| `lock` | 槽位初始化/退役与 worker 的代号校验、回调认领互斥 | 保留 spinlock |
| `close_reason` | worker 与 reactor 可能同时报告首次关闭；worker 持槽位锁，reactor 并非所有写入点都持该锁 | 保留首次原因 CAS，以及跨角色读取时的 acquire load |
| `recv_queued_bytes` | PROCESS：reactor 增加投递字节，worker 消费时减少；worker 的槽位锁没有覆盖 reactor 的增加操作 | PROCESS 保留 atomic RMW；BASE/THREAD 使用普通加减 |
| `last_recv_time` | reactor 更新 / 后台心跳扫描与 worker 查询读取 | 复用现有 double 存储，通过 getter/setter 执行 relaxed 原子读写；GCC/Clang 不加锁、不使用 CAS/RMW |

`sw_atomic_t` 是底层整数存储类型，实际原子性来自访问操作；仅保留这个 typedef 并不等于每次访问都要执行 RMW。
`dispatch_task()` 复用现有 Factory 虚调用，不再按模式选择计数。`BaseFactory::dispatch()` 固定使用
`ReceiveQueueMode::OWNER_REACTOR`；`ProcessFactory::dispatch()` 固定使用 `SHARED_PROCESS`，并在 IPC 投递失败时回滚。
只有 RECV_DATA 的有效载荷计入接收队列，CONNECT 证书或控制事件不计数。
计数方法以 C++14 模板参数确定策略，不传运行时布尔值，也不增加计数函数指针。
`prepare_receive_event()` 用于 PROCESS，持槽位锁并做 atomic 减法；
`prepare_receive_event_on_reactor()` 用于 BASE/THREAD，不加槽位锁，使用普通减法。
PROCESS 背压判断及跨角色的计数快照通过 `get_recv_queued_bytes()` 原子读取。
`ClientInfoSnapshot::recv_queued_bytes` 是调用者持有的复制值，改为普通 `uint32_t`。
`last_recv_time` 的所有读写统一通过访问方法，该字段位于 lock 之后的保留区域，连接复用时
只清零 active 与 lock 之间的一段内存；保留旧时间戳直到发布新 session 前写入实际建连时间，
不先清零时间戳，避免后台扫描与普通清零发生数据竞争，也省去一次无意义的原子写入。时间戳只用于活动度快照，
session、归属、protect 的一致性由槽位锁校验，不依赖该时间戳发布其他字段。
MSVC 使用现有 Interlocked 系列保守实现；GCC/Clang 使用 relaxed load/store，须以实际目标架构生成代码评估代价。
当前 GCC x86-64 构建中，字段重排使 `sizeof(Connection)` 从 296 经 288 降为 280 字节。
52 个字段的大小合计 278 字节，现仅有 2 字节填充；在保持字段类型与 8 字节对齐的前提下，
280 字节已是单纯重排的理论下限。active 仍在偏移 0，收发常用字段集中在前部，
锁与保留区边界仍用于单次 memset；百万个 Connection 相比 288 字节布局节省约 7.63 MiB。
`-O2` 的时间戳访问为普通 8 字节 load/store 加整数/SSE 寄存器搬运，不含 LOCK、CAS 或辅助函数调用。

## 现有跨角色字段：不能归类为无竞态

以下 13 个字段目前也是普通类型，但存在跨角色访问。这里记录真实访问关系，
不把已有普通类型、单一写入者或读取者持锁当作完整的无竞态证明。

| 字段 | 写入者 / 其他读取者 | 仍需明确的同步边界 |
| --- | --- | --- |
| `active` | reactor 发布/退役 / worker、遍历入口 | 发布/退役持槽位锁和 server mutex，通用遍历检查持槽位锁；其他乐观查找仍需在使用时重新验证 |
| `socket` | reactor 设置/释放 / 少量既有 API 校验 | 通用遍历与心跳线程已不再解引用；其他角色不能依靠裸指针持有 Socket 生命周期，单独加 atomic 也不解决释放竞态 |
| `worker_id` | reactor 调度时选择 / worker 的 getClientInfo | 调度结果的共享快照 |
| `ssl_ready` | reactor 完成握手 / worker 的连接校验、exists/getClientInfo | 握手完成到 worker 可见的发布规则 |
| `overflow` | reactor 的输出队列 / PROCESS worker 的 send-yield 判断 | 跨进程的输出反馈 |
| `uid` | worker 的 bind API / reactor 的 UID 调度 | bind 的锁必须与调度读取配套 |
| `websocket_status` | PHP worker 的握手/关闭，以及 reactor 协议路径 / 两端均读取 | 多写入方；不能作为 reactor 私有状态 |
| `websocket_compression` | PHP worker 的升级应答 / reactor 解帧和 worker 打包 | 协议升级的发布/确认边界 |
| `http2_stream` | reactor 协议识别 / PHP worker 的 HTTP/关闭处理 | 协议识别结果的发布和 fd 复用 |
| `close_errno` | reactor / worker 读取信息和 onClose | 错误码快照 |
| `send_queued_bytes` | reactor / worker/admin 信息查询 | 运行中统计快照 |
| `last_send_time` | reactor / worker/admin 查询 | 运行中统计快照 |
| `last_dispatch_time` | PROCESS worker / worker/admin 查询 | worker 写入和 getClientInfo 已持槽位锁；admin 仍有直接读取 |

主要证据路径：

- `src/server/master.cc`：`add_connection()`、`schedule_worker()`、`is_healthy_connection()`、`get_client_info()`。
- `src/server/reactor_thread.cc`：TLS 握手、输出事件、heartbeat 遍历、协议投递与物理释放。
- `src/server/process.cc`：PROCESS worker 的输出反馈判断。
- `ext-src/swoole_server.cc`：`bind()`、`protect()`、`exists()`、onClose。
- `ext-src/swoole_http_request.cc`、`swoole_http_response.cc`、`swoole_websocket_server.cc` 与
  `src/server/port.cc`、`src/protocol/websocket.cc`：worker/reactor 两侧的协议状态。

这批字段需要按其 IPC/协议快照语义继续处理，不能通过删掉 atomic 或只锁读取者来宣称修复。
尤其是 Socket/证书/解析对象的生命周期，atomic 指针只保证指针值访问，不能保证被指向的对象仍然存活。

## 心跳、遍历与强制关闭

PROCESS 的独立心跳线程承担整个连接范围的扫描和超时筛选；不能把全量扫描搬入 reactor，
否则百万连接的遍历本身会长期占用 event loop。后台扫描先 relaxed 读取 last_recv_time，
根据所有端口中最短的有效空闲期限跳过近期活跃的槽位；仅可能超时的槽位加锁，
校验 active、当前 session、所属 reactor、监听端口和 protect，复制 session_id/reactor_id 后释放锁。
后台线程不解引用连接 Socket，不修改 reactor 的关闭状态，也不在持有槽位锁时发送消息。

每个超时候选通过独立管道发送 `SW_SERVER_EVENT_CLOSE_FORCE`，携带 session_id。
管道初始化通过已有的 reactor 启动 barrier 发布，生产者在 barrier 之后启动，
不借用可能积压业务数据的 worker 管道。心跳线程独占写端 Socket，通过 `send_sync()` 同步等待发送，
管道满时等待可写并重试，超时或其他失败记录日志。
reactor 只校验收到的候选，重新检查 session、归属、当前收包时间和 protect，避免消息排队期间
出现新活动、保护状态变化或 fd 复用后错误关闭。全量扫描成本在后台线程，reactor 工作量与超时请求数相关；
每次管道回调最多处理 64 条心跳关闭请求，随后让出执行机会，剩余请求由水平触发的下一次就绪事件继续处理。

退出通过 condition_variable 唤醒周期等待，候选之间也检查停止标志；
正在执行的 `send_sync()` 依照 Socket 的写超时返回，停止生产者并 join 后才能销毁管道。
BASE、THREAD 和 PROCESS single_thread 保持原有的 reactor 定时器模式。

`foreach_connection_on_reactor()` 先按 fd 归属筛选槽位，随后只访问自己的连接。
`is_valid_connection()` 仅判断 active，不读取 Socket 指针或 fd_type。
普通事件入口仍比较 `conn->socket == event->socket`：这是拒绝过期事件的身份判断，不能用判空替代。
通用 `foreach_connection()` 只提供候选槽位，跨角色使用者必须在槽位锁内重新验证 session；
它不会持锁调用业务回调，也不授予 Socket 生命周期。

首次强制关闭复用 `close_abort`、`close_notification_started` 和 `close_waiting_worker`，停止事件监听、
标记输出应丢弃并通知 worker。worker 忙碌且尚未完成 onClose 分发时，后续强制关闭执行 shutdown，
释放待发缓存，但保留 fd/session 供迟到的 onClose 使用，不能把 fd 复用给新连接。
若回调已完成分发，或空闲时间超过 `heartbeat_idle_time + max_wait_time + 2 * heartbeat_check_interval`，
则释放 fd。后者是 worker 死亡或永久阻塞的资源回收兜底，不能保证回调送达；
回调认领仍至多一次，旧 session 的命令不能影响复用后的连接。此逻辑不增加 Connection 状态位。

active 发布与 min/max fd 更新、active 退役与 max fd 收缩使用同一个 server mutex，避免不同 reactor
在新连接尚未发布时收缩遍历范围。涉及两把锁时顺序固定为槽位锁 → server mutex。
server mutex 只协调同一进程内的 reactor；跨进程槽位验证仍依靠共享槽位锁，不能把它当作进程共享锁。
新增的锁只出现在 accept/close、空闲扫描和查询路径，不进入正常 recv/send 热点路径。
