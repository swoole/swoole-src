# 版本更新记录

从`v1.5`版本开始建立起严格的版本更新记录。目前平均迭代时间为每半年一个大版本，每`2-4`周一个小版本。

## 建议使用的PHP版本

* 7.2 [最新版]
* 7.3 [最新版]
* 7.4 [最新版]
* 8.0 [最新版]

## 建议使用的Swoole版本

两者的差别在于：`v4.8.x` 是主动迭代分支，`v4.4.x` 是**非**主动迭代分支，仅修复`BUG`

* [v4.8.x](https://github.com/swoole/swoole-src/tree/4.8.x) [稳定版]
* [v4.4.x](https://github.com/swoole/v4.4-lts) [稳定版]

!> `v4.x`以上版本可通过设置[enable_coroutine](/server/setting?id=enable_coroutine)关闭协程特性，使其变为非协程版本

## 版本类型

* `alpha` 特性预览版本，表示开发计划中的任务已完成，进行开放预览，可能会存在较多`BUG`
* `beta` 测试版本，表示已经可以用于开发环境测试，可能存在`BUG`
* `rc[1-n]` 候选发布版本，表示进入发布周期，正在做大范围的测试，在此期间仍可能发现`BUG`
* 无后缀即代表稳定版，表示此版本已开发完毕，可正式投入使用

## 查看当前版本信息

```shell
php --ri swoole
```

## v4.8.9

### 增强

- 支持 `Http2` 服务器下的 `http_auto_index` 选项

### 修复

- 优化 `Cookie` 解析器，支持传入 `HttpOnly` 选项
- 修复 #4657，Hook `socket_create` 方法返回类型问题
- 修复 `stream_select` 内存泄漏

### CLI 更新

- `CygWin` 下携带了 SSL 证书链，解决了 SSL 认证出错的问题
- 更新至 `PHP-8.1.5`

## v4.8.8

### 优化

- 将 SW_IPC_BUFFER_MAX_SIZE 减少到 64k
- 优化 http2 的 header_table_size 设置

### 修复

- 修复使用 enable_static_handler 下载静态文件大量套接字错误
- 修复 http2 server NPN 错误

## v4.8.7

### 增强

- 添加 curl_share 支持

### 修复

- 修复 arm32 架构下的未定义符号错误
- 修复 `clock_gettime()` 兼容性
- 修复当内核缺乏大块内存时，PROCESS 模式服务器发送失败的问题

## v4.8.6

### 修复

- 为 boost/context API 名称添加了前缀
- 优化配置选项

## v4.8.5

### 修复

- 还原 Table 的参数类型
- 修复使用 Websocket 协议接收错误数据时 crash

## v4.8.4

### 修复

- 修复 sockets hook 与 PHP-8.1 的兼容性
- 修复 Table 与 PHP-8.1 的兼容性
- 修复在部分情况下协程风格的 HTTP 服务器解析 `Content-Type` 为 `application/x-www-form-urlencoded` 的 `POST` 参数不符合预期

## v4.8.3

### 新增 API

- 增加 `Coroutine\Socket::isClosed()` 方法

### 修复

- 修复 curl native hook 在 php8.1 版本下的兼容性问题
- 修复 sockets hook 在 php8 下的兼容性问题
- 修复 sockets hook 函数返回值错误
- 修复 Http2Server sendfile 无法设置 content-type
- 优化 HttpServer date header 的性能，增加了 cache

## v4.8.2

### 修复

- 修复 proc_open hook 内存泄露的问题
- 修复 curl native hook 与 PHP-8.0、PHP-8.1 的兼容性问题
- 修复 Manager 进程中无法正常关闭连接的问题
- 修复 Manager 进程无法使用 sendMessage 的问题
- 修复 `Coroutine\Http\Server` 接收超大 POST 数据解析异常的问题
- 修复 PHP8 环境下致命错误时进行不能直接退出的问题
- 调整 coroutine `max_concurrency` 配置项，只允许在 `Co::set()` 中使用
- 调整 `Coroutine::join()` 忽略不存在的协程

## v4.8.1

### 新增 API

- 新增 `swoole_error_log_ex()` 和 `swoole_ignore_error()` 函数 (#4440) (@matyhtf)

### 增强

- 迁移 ext-swoole_plus 中的 admin api 到 ext-swoole (#4441) (@matyhtf)
- admin server 新增 get_composer_packages 命令 (swoole/library@07763f46) (swoole/library@8805dc05) (swoole/library@175f1797) (@sy-records) (@yunbaoi)
- 增加了写操作的 POST 方法请求限制 (swoole/library@ac16927c) (@yunbaoi)
- admin server 支持获取类方法信息 (swoole/library@690a1952) (@djw1028769140) (@sy-records)
- 优化 admin server 代码 (swoole/library#128) (swoole/library#131) (@sy-records)
- admin server 支持并发请求多个目标和并发请求多个 API (swoole/library#124) (@sy-records)
- admin server 支持获取接口信息 (swoole/library#130) (@sy-records)
- SWOOLE_HOOK_CURL 支持 CURLOPT_HTTPPROXYTUNNEL (swoole/library#126) (@sy-records)

### 修复

- join 方法禁止并发调用同一个协程 (#4442) (@matyhtf)
- 修复 Table 原子锁意外释放的问题 (#4446) (@Txhua) (@matyhtf)
- 修复丢失的 helper options (swoole/library#123) (@sy-records)
- 修复 get_static_property_value 命令参数错误 (swoole/library#129) (@sy-records)

## v4.8.0

### 向下不兼容改动

- 在 base 模式下，onStart 回调将始终在第一个工作进程 (worker id 为 0) 启动时回调，先于 onWorkerStart 执行 (#4389) (@matyhtf)

### 新增 API

- 新增 `Co::getStackUsage()` 方法 (#4398) (@matyhtf) (@twose)
- 新增 `Coroutine\Redis` 的一些 API (#4390) (@chrysanthemum)
- 新增 `Table::stats()` 方法 (#4405) (@matyhtf)
- 新增 `Coroutine::join()` 方法 (#4406) (@matyhtf)

### 新增功能

- 支持 server command (#4389) (@matyhtf)
- 支持 `Server::onBeforeShutdown` 事件回调 (#4415) (@matyhtf)

### 增强

- 当 Websocket pack 失败时设置错误码 (swoole/swoole-src@d27c5a5) (@matyhtf)
- 新增 `Timer::exec_count` 字段 (#4402) (@matyhtf)
- hook mkdir 支持使用 open_basedir ini 配置 (#4407) (@NathanFreeman)
- library 新增 vendor_init.php 脚本 (swoole/library@6c40b02) (@matyhtf)
- SWOOLE_HOOK_CURL 支持 CURLOPT_UNIX_SOCKET_PATH (swoole/library#121) (@sy-records)
- Client 支持设置 ssl_ciphers 配置项 (#4432) (@amuluowin)
- 为 `Server::stats()` 添加了一些新的信息 (#4410) (#4412) (@matyhtf)

### 修复

- 修复文件上传时，对文件名字进行不必要的 URL decode (swoole/swoole-src@a73780e) (@matyhtf)
- 修复 HTTP2 max_frame_size 问题 (#4394) (@twose)
- 修复 curl_multi_select bug #4393 (#4418) (@matyhtf)
- 修复丢失的 coroutine options (#4425) (@sy-records)
- 修复当发送缓冲区满的时候，连接无法被 close 的问题 (swoole/swoole-src@2198378) (@matyhtf)

## v4.7.1

### 增强

- `System::dnsLookup` 支持查询 `/etc/hosts` (#4341) (#4349) (@zmyWL) (@NathanFreeman)
- 增加对 mips64 的 boost context 支持 (#4358) (@dixyes)
- `SWOOLE_HOOK_CURL` 支持 `CURLOPT_RESOLVE` 选项 (swoole/library#107) (@sy-records)
- `SWOOLE_HOOK_CURL` 支持 `CURLOPT_NOPROGRESS` 选项 (swoole/library#117) (@sy-records)
- 增加对 riscv64 的 boost context 支持 (#4375) (@dixyes)

### 修复

- 修复 PHP-8.1 在 on shutdown 时产生的内存错误 (#4325) (@twose)
- 修复 8.1.0beta1 的不可序列化类 (#4335) (@remicollet)
- 修复多个协程递归创建目录失败的问题 (#4337) (@NathanFreeman)
- 修复 native curl 在外网发送大文件偶发超时的问题，以及在 CURL WRITEFUNCTION 中使用协程文件 API 出现 crash 的问题 (#4360) (@matyhtf)
- 修复 `PDOStatement::bindParam()` 期望参数1为字符串的问题 (swoole/library#116) (@sy-records)

## v4.7.0

### 新增 API

- 新增 `Process\Pool::detach()` 方法 (#4221) (@matyhtf)
- `Server` 支持 `onDisconnect` 回调函数 (#4230) (@matyhtf)
- 新增 `Coroutine::cancel()` 和 `Coroutine::isCanceled()` 方法 (#4247) (#4249) (@matyhtf)
- `Http\Client` 支持 `http_compression` 和 `body_decompression` 选项 (#4299) (@matyhtf)

### 增强

- 支持协程 MySQL 客户端在 `prepare` 时字段严格类型 (#4238) (@Yurunsoft)
- DNS 支持 `c-ares` 库 (#4275) (@matyhtf)
- `Server` 支持在多端口监听时给不同的端口配置心跳检测时间 (#4290) (@matyhtf)
- `Server` 的 `dispatch_mode` 支持 `SWOOLE_DISPATCH_CO_CONN_LB` 和 `SWOOLE_DISPATCH_CO_REQ_LB` 模式 (#4318) (@matyhtf)
- `ConnectionPool::get()` 支持 `timeout` 参数 (swoole/library#108) (@leocavalcante)
- Hook Curl 支持 `CURLOPT_PRIVATE` 选项 (swoole/library#112) (@sy-records)
- 优化 `PDOStatementProxy::setFetchMode()` 方法的函数声明 (swoole/library#109) (@yespire)

### 修复

- 修复使用线程上下文的时候，创建大量协程时抛出无法创建线程的异常 (8ce5041) (@matyhtf)
- 修复安装 Swoole 时 php_swoole.h 头文件丢失的问题 (#4239) (@sy-records)
- 修复 EVENT_HANDSHAKE 不向下兼容的问题 (#4248) (@sy-records)
- 修复 SW_LOCK_CHECK_RETURN 宏可能会调用两次函数的问题 (#4302) (@zmyWL)
- 修复 `Atomic\Long` 在 M1 芯片下的问题 (e6fae2e) (@matyhtf)
- 修复 `Coroutine\go()` 丢失返回值的问题 (swoole/library@1ed49db) (@matyhtf)
- 修复 `StringObject` 返回值类型问题 (swoole/library#111) (swoole/library#113) (@leocavalcante) (@sy-records)

### 内核

- 禁止 Hook 已经被 PHP 禁用的函数 (#4283) (@twose)

### 测试

- 新增 `Cygwin` 环境下的构建 (#4222) (@sy-records)
- 新增 `alpine 3.13` 和 `3.14` 的编译测试 (#4309) (@limingxinleo)

## v4.6.7

### 增强

- Manager 进程和 Task 同步进程支持调用`Process::signal()`函数 (#4190) (@matyhtf)

### 修复

- 修复信号不能被重复注册的问题 (#4170) (@matyhtf)
- 修复在 OpenBSD/NetBSD 上编译失败的问题 (#4188) (#4194) (@devnexen)
- 修复监听可写事件时特殊情况 onClose 事件丢失 (#4204) (@matyhtf)
- 修复 Symfony HttpClient 使用 native curl 的问题 (#4204) (@matyhtf)
- 修复`Http\Response::end()`方法总是返回 true 的问题 (swoole/swoole-src@66fcc35) (@matyhtf)
- 修复 PDOStatementProxy 产生的 PDOException (swoole/library#104) (@twose)

### 内核

- 重构 worker buffer，给 event data 加上 msg id 标志 (#4163) (@matyhtf)
- 修改 Request Entity Too Large 日志等级为 warning 级别 (#4175) (@sy-records)
- 替换 inet_ntoa and inet_aton 函数 (#4199) (@remicollet)
- 修改 output_buffer_size 默认值为 UINT_MAX (swoole/swoole-src@46ab345) (@matyhtf)

## v4.6.6

### 增强

- 支持在 FreeBSD 下 Master 进程退出后向 Manager 进程发送 SIGTERM 信号 (#4150) (@devnexen)
- 支持将 Swoole 静态编译到 PHP 中 (#4153) (@matyhtf)
- 支持 SNI 使用 HTTP 代理  (#4158) (@matyhtf)

### 修复

- 修复同步客户端异步连接的错误 (#4152) (@matyhtf)
- 修复 Hook 原生 curl multi 导致的内存泄漏 (swoole/swoole-src@91bf243) (@matyhtf)

## v4.6.5

### 新增 API

- 在 WaitGroup 中增加 count 方法(swoole/library#100) (@sy-records) (@deminy)

### 增强

- 支持原生 curl multi (#4093) (#4099) (#4101) (#4105) (#4113) (#4121) (#4147) (swoole/swoole-src@cd7f51c) (@matyhtf) (@sy-records) (@huanghantao)
- 允许在使用 HTTP/2 的 Response 中使用数组设置 headers

### 修复

- 修复 NetBSD 构建 (#4080) (@devnexen)
- 修复 OpenBSD 构建 (#4108) (@devnexen)
- 修复 illumos/solaris 构建，只有成员别名 (#4109) (@devnexen)
- 修复握手未完成时，SSL 连接的心跳检测不生效 (#4114) (@matyhtf)
- 修复 Http\Client 使用代理时`host`中存在`host:port`产生的错误 (#4124) (@Yurunsoft)
- 修复 Swoole\Coroutine\Http::request 中 header 和 cookie 的设置 (swoole/library#103) (@leocavalcante) (@deminy)

### 内核

- 支持 BSD 上的 asm context (#4082) (@devnexen)
- 在 FreeBSD 下使用 arc4random_buf 来实现 getrandom (#4096) (@devnexen)
- 优化 darwin arm64 context：删除 workaround 使用 label (#4127) (@devnexen)

### 测试

- 添加 alpine 的构建脚本 (#4104) (@limingxinleo)

## v4.6.4

### 新增 API

- 新增 Coroutine\Http::request, Coroutine\Http::post, Coroutine\Http::get 函数 (swoole/library#97) (@matyhtf)

### 增强

- 支持 ARM 64 构建 (#4057) (@devnexen)
- 支持在 Swoole TCP 服务器中设置 open_http_protocol (#4063) (@matyhtf)
- 支持 ssl 客户端只设置 certificate (91704ac) (@matyhtf)
- 支持 FreeBSD 的 tcp_defer_accept 选项 (#4049) (@devnexen)

### 修复

- 修复使用 Coroutine\Http\Client 时缺少代理授权的问题 (edc0552) (@matyhtf)
- 修复 Swoole\Table 的内存分配问题 (3e7770f) (@matyhtf)
- 修复 Coroutine\Http2\Client 并发连接时的 crash (630536d) (@matyhtf)
- 修复 DTLS 的 enable_ssl_encrypt 问题 (842733b) (@matyhtf)
- 修复 Coroutine\Barrier 内存泄漏(swoole/library#94) (@Appla) (@FMiS)
- 修复由 CURLOPT_PORT 和 CURLOPT_URL 顺序引起的偏移错误 (swoole/library#96) (@sy-records)
- 修复`Table::get($key, $field)`当字段类型为 float 时的错误 (08ea20c) (@matyhtf)
- 修复 Swoole\Table 内存泄漏 (d78ca8c) (@matyhtf)

## v4.4.24

### 修复

- 修复 http2 客户端并发连接时的 crash (#4079)

## v4.6.3

### 新增 API

- 新增 Swoole\Coroutine\go 函数 (swoole/library@82f63be) (@matyhtf)
- 新增 Swoole\Coroutine\defer 函数 (swoole/library@92fd0de) (@matyhtf)

### 增强

- 为 HTTP 服务器添加 compression_min_length 选项 (#4033) (@matyhtf)
- 允许在应用层设置 Content-Length HTTP 头 (#4041) (@doubaokun)

### 修复

- 修复程序达到文件打开限制时的 coredump (swoole/swoole-src@709813f) (@matyhtf)
- 修复 JIT 被禁用问题 (#4029) (@twose)
- 修复 `Response::create()` 参数错误问题 (swoole/swoole-src@a630b5b) (@matyhtf)
- 修复 ARM 平台下投递 task 时 task_worker_id 误报 (#4040) (@doubaokun)
- 修复 PHP8 开启 native curl hook 时的 coredump (#4042)(#4045) (@Yurunsoft) (@matyhtf)
- 修复 fatal error 时 shutdown 阶段的内存越界错误 (#4050) (@matyhtf)

### 内核

- 优化 ssl_connect/ssl_shutdown (#4030) (@matyhtf)
- 发生 fatal error 时直接退出进程 (#4053) (@matyhtf)

## v4.6.2

### 新增 API

- 新增 `Http\Request\getMethod()` 方法 (#3987) (@luolaifa000)
- 新增 `Coroutine\Socket->recvLine()` 方法 (#4014) (@matyhtf)
- 新增 `Coroutine\Socket->readWithBuffer()` 方法 (#4017) (@matyhtf)

### 增强

- 增强 `Response\create()` 方法，可以独立于 Server 使用 (#3998) (@matyhtf)
- 支持 `Coroutine\Redis->hExists` 在设置了 compatibility_mode 之后返回 bool 类型 (swoole/swoole-src@b8cce7c) (@matyhtf)
- 支持 `socket_read` 设置 PHP_NORMAL_READ 选项 (swoole/swoole-src@b1a0dcc) (@matyhtf)

### 修复

- 修复 `Coroutine::defer` 在 PHP8 下 coredump 的问题 (#3997) (@huanghantao)
- 修复当使用 thread context 的时候，错误设置 `Coroutine\Socket::errCode` 的问题 (swoole/swoole-src@004d08a) (@matyhtf)
- 修复在最新的 macos 下 Swoole 编译失败的问题 (#4007) (@matyhtf)
- 修复当 md5_file 参数传入 url 导致 php stream context 为空指针的问题 (#4016) (@ZhiyangLeeCN)

### 内核

- 使用 AIO 线程池 hook stdio（解决之前把 stdio 视为 socket 导致的多协程读写问题） (#4002) (@matyhtf)
- 重构 HttpContext (#3998) (@matyhtf)
- 重构 `Process::wait()` (#4019) (@matyhtf)

## v4.6.1

### 增强

- 增加 `--enable-thread-context` 编译选项 (#3970) (@matyhtf)
- 在操作 session_id 时检查连接是否存在 (#3993) (@matyhtf)
- 增强 CURLOPT_PROXY (swoole/library#87) (@sy-records)

### 修复

- 修复 pecl 安装中的最小 PHP 版本 (#3979) (@remicollet)
- 修复 pecl 安装时没有 `--enable-swoole-json` 和 `--enable-swoole-curl` 选项 (#3980) (@sy-records)
- 修复 openssl 线程安全问题 (b516d69f) (@matyhtf)
- 修复 enableSSL coredump (#3990) (@huanghantao)

### 内核

- 优化 ipc writev ，避免当事件数据为空时产生 coredump (9647678) (@matyhtf)

## v4.5.11

### 增强

- 优化 Swoole\Table (#3959) (@matyhtf)
- 增强 CURLOPT_PROXY (swoole/library#87) (@sy-records)

### 修复

- 修复 Table 递增和递减时不能清除所有列问题 (#3956) (@matyhtf) (@sy-records)
- 修复编译时产生的`clock_id_t`错误 (49fea171) (@matyhtf)
- 修复 fread bugs (#3972) (@matyhtf)
- 修复 ssl 多线程 crash (7ee2c1a0) (@matyhtf)
- 兼容 uri 格式错误导致报错 Invalid argument supplied for foreach (swoole/library#80) (@sy-records)
- 修复 trigger_error 参数错误 (swoole/library#86) (@sy-records)

## v4.6.0

### 向下不兼容改动

- 移除了`session id`的最大限制，不再重复 (#3879) (@matyhtf)
- 使用协程时禁用不安全功能，包括`pcntl_fork`/`pcntl_wait`/`pcntl_waitpid`/`pcntl_sigtimedwait` (#3880) (@matyhtf)
- 默认启用 coroutine hook (#3903) (@matyhtf)

### 移除

- 不再支持 PHP7.1 (4a963df) (9de8d9e) (@matyhtf)

### 废弃

- 将 `Event::rshutdown()` 标记为已弃用，请改用 Coroutine\run (#3881) (@matyhtf)

### 新增 API

- 支持 setPriority/getPriority (#3876) (@matyhtf)
- 支持 native-curl hook (#3863) (@matyhtf) (@huanghantao)
- 支持 Server 事件回调函数传递对象风格的参数，默认不传递对象风格的参数 (#3888) (@matyhtf)
- 支持 hook sockets 扩展 (#3898) (@matyhtf)
- 支持重复 header (#3905) (@matyhtf)
- 支持 SSL sni (#3908) (@matyhtf)
- 支持 hook stdio (#3924) (@matyhtf)
- 支持 stream_socket 的 capture_peer_cert 选项 (#3930) (@matyhtf)
- 添加 Http\Request::create/parse/isCompleted (#3938) (@matyhtf)
- 添加 Http\Response::isWritable (db56827) (@matyhtf)

### 增强

- Server 的所有时间精度都从 int 修改为 double (#3882) (@matyhtf)
- 在 swoole_client_select 函数里面检查 poll 函数的 EINTR 情况 (#3909) (@shiguangqi)
- 添加协程死锁检测 (#3911) (@matyhtf)
- 支持使用 SWOOLE_BASE 模式在另一个进程中关闭连接 (#3916) (@matyhtf)
- 优化 Server master 进程与 worker 进程通信的性能，减少内存拷贝 (#3910) (@huanghantao) (@matyhtf)

### 修复

- 当 Coroutine\Channel 被关闭时，pop 出里面所有的数据 (960431d) (@matyhtf)
- 修复使用 JIT 时的内存错误 (#3907) (@twose)
- 修复 `port->set()` dtls 编译错误 (#3947) (@Yurunsoft)
- 修复 connection_list 错误 (#3948) (@sy-records)
- 修复 ssl verify (#3954) (@matyhtf)
- 修复 Table 递增和递减时不能清除所有列问题 (#3956) (@matyhtf) (@sy-records)
- 修复使用 LibreSSL 2.7.5 编译失败 (#3962) (@matyhtf)
- 修复未定义的常量 CURLOPT_HEADEROPT 和 CURLOPT_PROXYHEADER (swoole/library#77) (@sy-records)

### 内核

- 默认情况下忽略 SIGPIPE 信号 (9647678) (@matyhtf)
- 支持同时运行 PHP 协程和 C 协程 (c94bfd8) (@matyhtf)
- 添加 get_elapsed 测试 (#3961) (@luolaifa000)
- 添加 get_init_msec 测试 (#3964) (@luffluo)

## v4.5.10

### 修复

- 修复使用 Event::cycle 时产生的 coredump (93901dc) (@matyhtf)
- 兼容 PHP8 (f0dc6d3) (@matyhtf)
- 修复 connection_list 错误 (#3948) (@sy-records)

## v4.4.23

### 修复

- 修复 Swoole\Table 自减时数据错误 (bcd4f60d)(0d5e72e7) (@matyhtf)
- 修复同步客户端错误信息 (#3784)
- 修复解析表单数据边界时出现的内存溢出问题 (#3858)
- 修复 channel 的bug，关闭后无法 pop 已有数据

## v4.5.9

### 增强

- 为 Coroutine\Http\Client 添加 SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED 常量 (#3873) (@sy-records)

### 修复

- 兼容 PHP8 (#3868) (#3869) (#3872) (@twose) (@huanghantao) (@doubaokun)
- 修复未定义的常量 CURLOPT_HEADEROPT 和 CURLOPT_PROXYHEADER (swoole/library#77) (@sy-records)
- 修复 CURLOPT_USERPWD (swoole/library@7952a7b) (@twose)

## v4.5.8

### 新增 API

- 新增 swoole_error_log 函数，优化log_rotation (swoole/swoole-src@67d2bff) (@matyhtf)
- readVector 和 writeVector 支持 SSL (#3857) (@huanghantao)

### 增强

- 当子进程退出后，让 System::wait 退出阻塞 (#3832) (@matyhtf)
- DTLS 支持 16K 的包 (#3849) (@matyhtf)
- Response::cookie 方法支持 priority 参数 (#3854) (@matyhtf)
- 支持更多的 CURL 选项 (swoole/library#71) (@sy-records)
- 处理 CURL HTTP header 没有区分名字大小写导致被覆盖问题 (swoole/library#76) (@filakhtov) (@twose) (@sy-records)

### 修复

- 修复 readv_all 和 writev_all 错误处理 EAGAIN 的问题 (#3830) (@huanghantao)
- 修复 PHP8 编译警告的问题 (swoole/swoole-src@03f3fb0) (@matyhtf)
- 修复 Swoole\Table 二进制安全的问题 (#3842) (@twose)
- 修复 MacOS 下 System::writeFile 追加文件覆盖的问题 (swoole/swoole-src@a71956d) (@matyhtf)
- 修复 CURL 的 CURLOPT_WRITEFUNCTION (swoole/library#74) (swoole/library#75) (@sy-records)
- 修复解析 HTTP form-data 时内存溢出的问题 (#3858) (@twose)
- 修复在 PHP8 中 `is_callable()` 无法访问类私有方法的问题 (#3859) (@twose)

### 内核

- 重构内存分配函数，使用 SwooleG.std_allocator (#3853) (@matyhtf)
- 重构管道 (#3841) (@matyhtf)

## v4.5.7

### 新增 API

- Coroutine\Socket 客户端新增 writeVector, writeVectorAll, readVector, readVectorAll 方法 (#3764) (@huanghantao)

### 增强

- 为 server->stats 增加 task_worker_num 和 dispatch_count (#3771) (#3806) (@sy-records) (@matyhtf)
- 添加了扩展依赖项，包括 json, mysqlnd, sockets (#3789) (@remicollet)
- 限制 server->bind 的 uid 最小值为 INT32_MIN (#3785) (@sy-records)
- 为 swoole_substr_json_decode 添加了编译选项，支持负偏移量 (#3809) (@matyhtf)
- 支持 CURL 的 CURLOPT_TCP_NODELAY 选项 (swoole/library#65) (@sy-records) (@deminy)

### 修复

- 修复同步客户端连接信息错误 (#3784) (@twose)
- 修复 hook scandir 函数的问题 (#3793) (@twose)
- 修复协程屏障 barrier 中的错误 (swoole/library#68) (@sy-records)

### 内核

- 使用 boost.stacktrace 优化 print-backtrace (#3788) (@matyhtf)

## v4.5.6

### 新增 API

- 新增 [swoole_substr_unserialize](/functions?id=swoole_substr_unserialize) 和 [swoole_substr_json_decode](/functions?id=swoole_substr_json_decode) (#3762) (@matyhtf)

### 增强

- 修改 `Coroutine\Http\Server` 的 `onAccept` 方法为私有 (dfcc83b) (@matyhtf)

### 修复

- 修复 coverity 的问题 (#3737) (#3740) (@matyhtf)
- 修复 Alpine 环境下的一些问题 (#3738) (@matyhtf)
- 修复 swMutex_lockwait (0fc5665) (@matyhtf)
- 修复 PHP-8.1 安装失败 (#3757) (@twose)

### 内核

- 为 `Socket::read/write/shutdown` 添加了活性检测 (#3735) (@matyhtf)
- 将 session_id 和 task_id 的类型更改为 int64 (#3756) (@matyhtf)

## v4.5.5

!> 此版本增加了[配置项](/server/setting)检测功能，如果设置了不是Swoole提供的选项，会产生一个Warning。

```shell
PHP Warning:  unsupported option [foo] in @swoole-src/library/core/Server/Helper.php 
```

```php
$http = new Swoole\Http\Server('0.0.0.0', 9501);

$http->set(['foo' => 'bar']);

$http->on('request', function ($request, $response) {
    $response->header("Content-Type", "text/html; charset=utf-8");
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});

$http->start();
```

### 新增 API

- 增加 Process\Manager，修改 Process\ProcessManager 为别名 (swoole/library#eac1ac5) (@matyhtf)
- 支持 HTTP2 服务器 GOAWAY (#3710) (@doubaokun)
- 增加 `Co\map()` 函数 (swoole/library#57) (@leocavalcante)

### 增强

- 支持 http2 unix socket 客户端 (#3668) (@sy-records)
- 当 worker 进程退出之后设置 worker 进程状态为 SW_WORKER_EXIT (#3724) (@matyhtf)
- 在 `Server::getClientInfo()` 的返回值中增加 send_queued_bytes 和 recv_queued_bytes (#3721) (#3731) (@matyhtf) (@Yurunsoft)
- Server 支持 stats_file 配置选项 (#3725) (@matyhtf) (@Yurunsoft)

### 修复

- 修复 PHP8 下的编译问题 (zend_compile_string change) (#3670) (@twose)
- 修复 PHP8 下的编译问题 (ext/sockets compatibility) (#3684) (@twose)
- 修复 PHP8 下的编译问题 (php_url_encode_hash_ex change) (#3713) (@remicollet)
- 修复从'const char*' to 'char*'的错误类型转化 (#3686) (@remicollet)
- 修复 HTTP2 client 在 HTTP proxy 下无法工作的问题 (#3677) (@matyhtf) (@twose)
- 修复 PDO 断线重连时数据混乱的问题 (swoole/library#54) (@sy-records)
- 修复 UDP Server 使用ipv6时端口解析错误
- 修复 Lock::lockwait 超时无效的问题

## v4.5.4

### 向下不兼容改动

- SWOOLE_HOOK_ALL 包括 SWOOlE_HOOK_CURL (#3606) (@matyhtf)
- 移除 ssl_method，增加 ssl_protocols (#3639) (@Yurunsoft)

### 新增 API

- 增加数组的 firstKey 和 lastKey 方法 (swoole/library#51) (@sy-records)

### 增强

- 增加 Websocket 服务器的 open_websocket_ping_frame, open_websocket_pong_frame 配置项 (#3600) (@Yurunsoft)

### 修复

- 修复文件大于 2G 时候，fseek ftell 不正确的问题 (#3619) (@Yurunsoft)
- 修复 Socket barrier 的问题 (#3627) (@matyhtf)
- 修复 http proxy handshake 的问题 (#3630) (@matyhtf)
- 修复对端发送 chunk 数据的时候，解析 HTTP Header 出错的问题 (#3633) (@matyhtf)
- 修复 zend_hash_clean 断言失败的问题 (#3634) (@twose)
- 修复不能从事件循环移除 broken fd 的问题 (#3650) (@matyhtf)
- 修复收到无效的 packet 时导致 coredump 的问题 (#3653) (@matyhtf)
- 修复 array_key_last 的 bug (swoole/library#46) (@sy-records)

### 内核

- 代码优化 (#3615) (#3617) (#3622) (#3635) (#3640) (#3641) (#3642) (#3645) (#3658) (@matyhtf)
- 当往 Swoole Table 写入数据的时候减少不必要的内存操作 (#3620) (@matyhtf)
- 重构 AIO (#3624) (@Yurunsoft)
- 支持 readlink/opendir/readdir/closedir hook (#3628) (@matyhtf)
- 优化 swMutex_create, 支持 SW_MUTEX_ROBUST (#3646) (@matyhtf)

## v4.5.3

### 新增API

- 增加 `Swoole\Process\ProcessManager` (swoole/library#88f147b) (@huanghantao)
- 增加 ArrayObject::append, StringObject::equals (swoole/library#f28556f) (@matyhtf)
- 增加 [Coroutine::parallel](/coroutine/coroutine?id=parallel) (swoole/library#6aa89a9) (@matyhtf)
- 增加 [Coroutine\Barrier](/coroutine/barrier) (swoole/library#2988b2a) (@matyhtf)

### 增强

- 增加 usePipelineRead 来支持 http2 client streaming (#3354) (@twose)
- http 客户端下载文件时，在接受数据前不创建文件 (#3381) (@twose)
- http client 支持`bind_address`和`bind_port`配置 (#3390) (@huanghantao)
- http client 支持`lowercase_header`配置 (#3399) (@matyhtf)
- `Swoole\Server`支持`tcp_user_timeout`配置 (#3404) (@huanghantao)
- `Coroutine\Socket`增加 event barrier 来减少协程切换 (#3409) (@matyhtf)
- 为特定的 swString 增加`memory allocator` (#3418) (@matyhtf)
- cURL 支持`__toString` (swoole/library#38) (@twose)
- 支持直接在 WaitGroup 构造函数中设置`wait count` (swoole/library#2fb228b8) (@matyhtf)
- 增加`CURLOPT_REDIR_PROTOCOLS` (swoole/library#46) (@sy-records)
- http1.1 server 支持 trailer (#3485) (@huanghantao)
- 协程 sleep 时间小于 1ms 将会 yield 当前协程 (#3487) (@Yurunsoft)
- http static handler 支持软连接的文件 (#3569) (@LeiZhang-Hunter)
- 在 Server 调用完 close 方法之后立刻关闭 WebSocket 连接 (#3570) (@matyhtf)
- 支持 hook stream_set_blocking (#3585) (@Yurunsoft)
- 异步 HTTP2 server 支持流控 (#3486) (@huanghantao) (@matyhtf)
- 释放 socket buffer 在 onPackage 回调函数执行完 (#3551) (@huanghantao) (@matyhtf)

### 修复

- 修复 WebSocket coredump, 处理协议错误的状态 (#3359) (@twose)
- 修复 swSignalfd_setup 函数以及 wait_signal 函数里的空指针错误 (#3360) (@twose)
- 修复在设置了 dispatch_func 时候，调用`Swoole\Server::close`会报错的问题 (#3365) (@twose)
- 修复`Swoole\Redis\Server::format`函数中 format_buffer 初始化问题 (#3369) (@matyhtf) (@twose)
- 修复 MacOS 上无法获取 mac 地址的问题 (#3372) (@twose)
- 修复 MySQL 测试用例 (#3374) (@qiqizjl)
- 修复多处 PHP8 兼容性问题 (#3384) (#3458) (#3578) (#3598) (@twose)
- 修复 hook 的 socket write 中丢失了 php_error_docref, timeout_event 和返回值问题 (#3383) (@twose)
- 修复异步 Server 无法在`WorkerStart`回调函数中关闭 Server 的问题 (#3382) (@huanghantao)
- 修复心跳线程在操作 conn->socket 的时候，可能会发生 coredump 的问题 (#3396) (@huanghantao)
- 修复 send_yield 的逻辑问题 (#3397) (@twose) (@matyhtf)
- 修复 Cygwin64 上的编译问题 (#3400) (@twose)
- 修复 WebSocket finish 属性无效的问题 (#3410) (@matyhtf)
- 修复遗漏的 MySQL transaction 错误状态 (#3429) (@twose)
- 修复 hook 后的`stream_select`与 hook 之前返回值行为不一致的问题 (#3440) (@Yurunsoft)
- 修复使用`Coroutine\System`来创建子进程时丢失`SIGCHLD`信号的问题 (#3446) (@huanghantao)
- 修复`sendwait`不支持 SSL 的问题 (#3459) (@huanghantao)
- 修复`ArrayObject`和`StringObject`的若干问题 (swoole/library#44) (@matyhtf)
- 修复 mysqli 异常信息错误 (swoole/library#45) (@sy-records)
- 修复当设置`open_eof_check`后，`Swoole\Client`无法获取正确的`errCode`的问题 (#3478) (@huanghantao)
- 修复 MacOS 上 `atomic->wait()`/`wakeup()`的若干问题 (#3476) (@Yurunsoft)
- 修复`Client::connect`连接拒绝的时候，返回成功状态的问题 (#3484) (@matyhtf)
- 修复 alpine 环境下 nullptr_t 没有被声明的问题 (#3488) (@limingxinleo)
- 修复 HTTP Client 下载文件的时候，double-free 的问题 (#3489) (@Yurunsoft)
- 修复`Server`被销毁时候，`Server\Port`没释放导致的内存泄漏问题 (#3507) (@twose)
- 修复 MQTT 协议解析问题 (318e33a) (84d8214) (80327b3) (efe6c63) (@GXhua) (@sy-records)
- 修复`Coroutine\Http\Client->getHeaderOut`方法导致的 coredump 问题 (#3534) (@matyhtf)
- 修复 SSL 验证失败后，丢失了错误信息的问题 (#3535) (@twose)
- 修复 README 中，`Swoole benchmark`链接错误的问题 (#3536) (@sy-records) (@santalex)
- 修复在`HTTP header/cookie`中使用`CRLF`后导致的`header`注入问题 (#3539) (#3541) (#3545) (@chromium1337) (@huanghantao)
- 修复 issue #3463 中提到的变量错误的问题 (#3547) (chromium1337) (@huanghantao)
- 修复 pr #3463 中提到的错别字问题 (#3547) (@deminy)
- 修复协程 WebSocket 服务器 frame->fd 为空的问题 (#3549) (@huanghantao)
- 修复心跳线程错误判断连接状态导致的连接泄漏问题 (#3534) (@matyhtf)
- 修复`Process\Pool`中阻塞了信号的问题 (#3582) (@huanghantao) (@matyhtf)
- 修复`SAPI`中使用 send headers 的问题 (#3571) (@twose) (@sshymko)
- 修复`CURL`执行失败的时候，未设置`errCode`和`errMsg`的问题 (swoole/library#1b6c65e) (@sy-records)
- 修复当调用了`setProtocol`方法后，`swoole_socket_coro`accept coredump 的问题 (#3591) (@matyhtf)

### 内核

- 使用 C++风格 (#3349) (#3351) (#3454) (#3479) (#3490) (@huanghantao) (@matyhtf)
- 增加`Swoole known strings`来提高`PHP`对象读属性的性能 (#3363) (@huanghantao)
- 多处代码优化 (#3350) (#3356) (#3357) (#3423) (#3426) (#3461) (#3463) (#3472) (#3557) (#3583) (@huanghantao) (@twose) (@matyhtf)
- 多处测试代码的优化 (#3416) (#3481) (#3558) (@matyhtf)
- 简化`Swoole\Table`的`int`类型 (#3407) (@matyhtf)
- 增加`sw_memset_zero`，并且替换`bzero`函数 (#3419) (@CismonX)
- 优化日志模块 (#3432) (@matyhtf)
- 多处 libswoole 重构 (#3448) (#3473) (#3475) (#3492) (#3494) (#3497) (#3498) (#3526) (@matyhtf)
- 多处头文件引入重构 (#3457) (@matyhtf) (@huanghantao)
- 增加`Channel::count()`和`Channel::get_bytes()` (f001581) (@matyhtf)
- 增加`scope guard` (#3504) (@huanghantao)
- 增加 libswoole 覆盖率测试 (#3431) (@huanghantao)
- 增加 lib-swoole/ext-swoole MacOS 环境的测试 (#3521) (@huanghantao)
- 增加 lib-swoole/ext-swoole Alpine 环境的测试 (#3537) (@limingxinleo)

## v4.5.2

[v4.5.2](https://github.com/swoole/swoole-src/releases/tag/v4.5.2)，这是一个 BUG 修复版本, 没有任何向下不兼容改动

### 增强

- 支持 `Server->set(['log_rotation' => SWOOLE_LOG_ROTATION_DAILY])` 来按日期生成日志 (#3311) (@matyhtf)
- 支持 `swoole_async_set(['wait_signal' => true])`, 若存在信号监听器时 reactor 将不会退出 (#3314) (@matyhtf)
- 支持 `Server->sendfile` 发送空文件 (#3318) (@twose)
- 优化 worker 忙闲警告信息 (#3328) (@huanghantao)
- 优化 HTTPS 代理下关于 Host 标头的配置 (使用 ssl_host_name 来配置) (#3343) (@twose)
- SSL 默认使用 ecdh auto 模式 (#3316) (@matyhtf)
- SSL 客户端在连接断开时使用静默退出 (#3342) (@huanghantao)

### 修复

- 修复 `Server->taskWait` 在 OSX 平台上的问题 (#3330) (@matyhtf)
- 修复 MQTT 协议解析错误的 bug (8dbf506b) (@guoxinhua) (2ae8eb32) (@twose)
- 修复 Content-Length int 类型溢出的问题 (#3346) (@twose)
- 修复 PRI 包长度检查缺失的问题 (#3348) (@twose)
- 修复 CURLOPT_POSTFIELDS 无法置空的问题 (swoole/library@ed192f64) (@twose)
- 修复 最新的连接对象在接收到下一个连接之前无法被释放的问题 (swoole/library@1ef79339) (@twose)

### 内核

- Socket 写入零拷贝特性 (#3327) (@twose)
- 使用 swoole_get_last_error/swoole_set_last_error 两个来替代全局变量读写 (e25f262a) (@matyhtf) (#3315) (@huanghantao)

## v4.5.1

[v4.5.1](https://github.com/swoole/swoole-src/releases/tag/v4.5.1)，这是一个 BUG 修复版本, 补充了本应在`v4.5.0`引入的 System 文件函数废弃标记

### 增强

- 支持 hook 下的 socket_context 的 bindto 配置 (#3275) (#3278) (@codinghuang)
- 支持 client::sendto 自动 dns 解析地址 (#3292) (@codinghuang)
- Process->exit(0)将会直接导致进程退出, 若要执行 shutdown_functions 再退出请使用 PHP 提供的 exit (a732fe56) (@matyhtf)
- 支持配置`log_date_format`以更改日志日期格式, `log_date_with_microseconds`在日志中显示微秒时间戳 (baf895bc) (@matyhtf)
- 支持 CURLOPT_CAINFO and CURLOPT_CAPATH (swoole/library#32) (@sy-records)
- 支持 CURLOPT_FORBID_REUSE (swoole/library#33) (@sy-records)

### 修复

- 修复 32 位下构建失败 (#3276) (#3277) (@remicollet) (@twose)
- 修复协程 Client 重复连接时没有 EISCONN 错误信息的问题 (#3280) (@codinghuang)
- 修复 Table 模块中潜在的 bug (d7b87b65) (@matyhtf)
- 修复 Server 中由于未定义行为导致的空指针(防御性编程) (#3304) (#3305) (@twose)
- 修复心跳配置开启后产生空指针错误的问题 (#3307) (@twose)
- 修复 mysqli 配置不生效 (swoole/library#35)
- 修复 response 中不规范的 header(缺少空格)时解析的问题 (swoole/library#27) (@Yurunsoft)

### 废弃

- 将 Coroutine\System::(fread/fgets/fwrite)等方法标记为废弃 (请使用 hook 特性替代, 直接使用 PHP 提供的文件函数) (c7c9bb40) (@twose)

### 内核

- 使用 zend_object_alloc 为自定义对象分配内存 (cf1afb25) (@twose)
- 一些优化, 为日志模块添加更多配置项 (#3296) (@matyhtf)
- 大量代码优化工作和增加单测 (swoole/library) (@deminy)

## v4.5.0

[v4.5.0](https://github.com/swoole/swoole-src/releases/tag/v4.5.0)，这是一个大版本更新, 仅删除了一些在 v4.4.x 已标记废弃的模块

### 新增 API

- DTLS 支持, 现在可以此功能来构建 WebRTC 应用 (#3188) (@matyhtf)
- 内置的`FastCGI`客户端, 可以通过一行代码来代理请求到 FPM 或是调用 FPM 应用 (swoole/library#17) (@twose)
- `Co::wait`, `Co::waitPid` (用于回收子进程) `Co::waitSignal` (用于等待信号) (#3158) (@twose)
- `Co::waitEvent` (用于等待 socket 上发生的指定的事件) (#3197) (@twose)
- `Co::set(['exit_condition' => $callable])` (用于自定义程序退出的条件) (#2918) (#3012) (@twose)
- `Co::getElapsed` (获取协程运行的时间以便于分析统计或找出僵尸协程) (#3162) (@doubaokun)
- `Socket::checkLiveness` (通过系统调用判断连接是否活跃), `Socket::peek` (窥视读缓冲区) (#3057) (@twose)
- `Socket->setProtocol(['open_fastcgi_protocol' => $bool])` (内置的 FastCGI 解包支持) (#3103) (@twose)
- `Server::get(Master|Manager|Worker)Pid`, `Server::getWorkerId` (获取异步 Server 单例和其信息) (#2793) (#3019) (@matyhtf)
- `Server::getWorkerStatus` (获取 worker 进程状态, 返回常量 SWOOLE_WORKER_BUSY, SWOOLE_WORKER_IDLE 以表示忙闲状态) (#3225) (@matyhtf)
- `Server->on('beforeReload', $callable)` 和 `Server->on('afterReload', $callable)` (服务重启事件, 发生在 manager 进程) (#3130) (@hantaohuang)
- `Http\Server`静态文件处理器现在支持`http_index_files`和`http_autoindex`配置 (#3171) (@hantaohuang)
- `Http2\Client->read(float $timeout = -1)`方法支持读取流式的响应 (#3011) (#3117) (@twose)
- `Http\Request->getContent` (rawContent 方法的别名) (#3128) (@hantaohuang)
- `swoole_mime_type_(add|set|delete|get|exists)()` (mime 相关 APIs, 可增删查改内置的 mime 类型) (#3134) (@twose)

### 增强

- 优化 master 和 worker 进程间的内存拷贝(极限情况下提升了四倍性能) (#3075) (#3087) (@hantaohuang)
- 优化 WebSocket 派遣逻辑 (#3076) (@matyhtf)
- 优化 WebSocket 构造帧时的一次内存拷贝 (#3097) (@matyhtf)
- 优化 SSL 验证模块 (#3226) (@matyhtf)
- 分离 SSL accept 和 SSL handshake, 解决慢速 SSL 客户端可能会造成协程服务器假死的问题 (#3214) (@twose)
- 支持 MIPS 架构 (#3196) (@ekongyun)
- UDP 客户端现在可以自动解析传入的域名 (#3236) (#3239) (@huanghantao)
- Coroutine\Http\Server 增加支持了一些常用的选项 (#3257) (@twose)
- 支持在 WebSocket 握手时设置 cookie (#3270) (#3272) (@twose)
- 支持 CURLOPT_FAILONERROR (swoole/library#20) (@sy-records)
- 支持 CURLOPT_SSLCERTTYPE, CURLOPT_SSLCERT, CURLOPT_SSLKEYTYPE, CURLOPT_SSLKEY (swoole/library#22) (@sy-records)
- 支持 CURLOPT_HTTPGET (swoole/library@d730bd08) (@shiguangqi)

### 移除

- 移除`Runtime::enableStrictMode`方法 (b45838e3) (@twose)
- 移除`Buffer`类 (559a49a8) (@twose)

### 内核相关

- 新的 C++的 API: coroutine::async 函数传入 lambda 即可发起异步线程任务 (#3127) (@matyhtf)
- 重构底层 event-API 中的整数型 fd 为 swSocket 对象 (#3030) (@matyhtf)
- 所有核心的 C 文件都已转化为 C++文件 (#3030) (71f987f3) (@matyhtf)
- 一系列代码优化 (#3063) (#3067) (#3115) (#3135) (#3138) (#3139) (#3151) (#3168) (@hantaohuang)
- 对于头文件的规范化优化 (#3051) (@matyhtf)
- 重构`enable_reuse_port`配置项使其更加规范 (#3192) (@matyhtf)
- 重构 Socket 相关 API 使其更加规范 (#3193) (@matyhtf)
- 通过缓冲区预测来减少一次不必要的系统调用 (3b5aa85d) (@matyhtf)
- 移除底层的刷新定时器 swServerGS::now, 直接使用时间函数获取时间 (#3152) (@hantaohuang)
- 优化协议配置器 (#3108) (@twose)
- 兼容性更好的 C 结构初始化写法 (#3069) (@twose)
- bit 字段统一为 uchar 类型 (#3071) (@twose)
- 支持并行测试, 速度更快 (#3215) (@twose)

### 修复

- 修复 enable_delay_receive 开启后 onConnect 无法触发的问题 (#3221) (#3224) (@matyhtf)
- 所有其它的 bug 修复都已合并到 v4.4.x 分支并在更新日志中体现, 在此不再赘述

## v4.4.22

### 修复

- 修复 HTTP2 client 在 HTTP proxy 下无法工作的问题 (#3677) (@matyhtf) (@twose)
- 修复 PDO 断线重连时数据混乱的问题 (swoole/library#54) (@sy-records)
- 修复 swMutex_lockwait (0fc5665) (@matyhtf)
- 修复 UDP Server 使用ipv6时端口解析错误
- 修复 systemd fds 的问题

## v4.4.20

[v4.4.20](https://github.com/swoole/swoole-src/releases/tag/v4.4.20)，这是一个BUG修复版本, 没有任何向下不兼容改动

### 修复

- 修复在设置了 dispatch_func 时候，调用`Swoole\Server::close`会报错的问题 (#3365) (@twose)
- 修复`Swoole\Redis\Server::format`函数中 format_buffer 初始化问题 (#3369) (@matyhtf) (@twose)
- 修复 MacOS 上无法获取 mac 地址的问题 (#3372) (@twose)
- 修复 MySQL 测试用例 (#3374) (@qiqizjl)
- 修复异步 Server 无法在`WorkerStart`回调函数中关闭 Server 的问题 (#3382) (@huanghantao)
- 修复遗漏的 MySQL transaction 错误状态 (#3429) (@twose)
- 修复 HTTP Client 下载文件的时候，double-free 的问题 (#3489) (@Yurunsoft)
- 修复`Coroutine\Http\Client->getHeaderOut`方法导致的 coredump 问题 (#3534) (@matyhtf)
- 修复在`HTTP header/cookie`中使用`CRLF`后导致的`header`注入问题 (#3539) (#3541) (#3545) (@chromium1337) (@huanghantao)
- 修复协程 WebSocket 服务器 frame->fd 为空的问题 (#3549) (@huanghantao)
- 修复 hook phpredis 产生的`read error on connection`问题 (#3579) (@twose)
- 修复 MQTT 协议解析问题 (#3573) (#3517) (9ad2b455) (@GXhua) (@sy-records)

## v4.4.19

[v4.4.19](https://github.com/swoole/swoole-src/releases/tag/v4.4.19)，这是一个 BUG 修复版本, 没有任何向下不兼容改动

!> 注意: v4.4.x 不再是主要的维护版本，仅在必要时修复 BUG

### 修复

- 从 v4.5.2 合并了所有 bug 修复补丁

## v4.4.18

[v4.4.18](https://github.com/swoole/swoole-src/releases/tag/v4.4.18)，这是一个 BUG 修复版本, 没有任何向下不兼容改动

### 增强

- UDP 客户端现在可以自动解析传入的域名 (#3236) (#3239) (@huanghantao)
- CLI 模式下不再关闭 stdout 和 stderr (显示在 shutdown 之后产生的错误日志) (#3249) (@twose)
- Coroutine\Http\Server 增加支持了一些常用的选项 (#3257) (@twose)
- 支持在 WebSocket 握手时设置 cookie (#3270) (#3272) (@twose)
- 支持 CURLOPT_FAILONERROR (swoole/library#20) (@sy-records)
- 支持 CURLOPT_SSLCERTTYPE, CURLOPT_SSLCERT, CURLOPT_SSLKEYTYPE, CURLOPT_SSLKEY (swoole/library#22) (@sy-records)
- 支持 CURLOPT_HTTPGET (swoole/library@d730bd08) (@shiguangqi)
- 尽可能地兼容了所有 PHP-Redis 扩展的版本 (不同版本的构造函数传参不同) (swoole/library#24) (@twose)
- 禁止克隆连接对象 (swoole/library#23) (@deminy)

### 修复

- 修复 SSL 握手失败的问题 (dc5ac29a) (@twose)
- 修复生成错误信息时产生的内存错误 (#3229) (@twose)
- 修复空白的 proxy 验证信息 (#3243) (@twose)
- 修复 Channel 的内存泄漏问题 (并非真正的内存泄漏) (#3260) (@twose)
- 修复 Co\Http\Server 在循环引用时产生的一次性内存泄露 (#3271) (@twose)
- 修复`ConnectionPool->fill`中的书写错误 (swoole/library#18) (@NHZEX)
- 修复 curl 客户端遭遇重定向时没有更新连接的问题 (swoole/library#21) (@doubaokun)
- 修复产生 ioException 时空指针的问题 (swoole/library@4d15a4c3) (@twose)
- 修复 ConnectionPool@put 传入 null 时没有归还新连接导致的死锁问题 (swoole/library#25) (@Sinute)
- 修复 mysqli 代理实现导致的 write_property 错误 (swoole/library#26) (@twose)

## v4.4.17

[v4.4.17](https://github.com/swoole/swoole-src/releases/tag/v4.4.17)，这是一个 BUG 修复版本, 没有任何向下不兼容改动

### 增强

- 提升 SSL 服务器的性能 (#3077) (85a9a595) (@matyhtf)
- 移除 HTTP 头大小限制 (#3187) limitation (@twose)
- 支持 MIPS (#3196) (@ekongyun)
- 支持 CURLOPT_HTTPAUTH (swoole/library@570318be) (@twose)

### 修复

- 修复 package_length_func 的行为和可能的一次性内存泄漏 (#3111) (@twose)
- 修复 HTTP 状态码 304 下的错误行为 (#3118) (#3120) (@twose)
- 修复 Trace 日志错误的宏展开导致的内存错误 (#3142) (@twose)
- 修复 OpenSSL 函数签名 (#3154) (#3155) (@twose)
- 修复 SSL 错误信息 (#3172) (@matyhtf) (@twose)
- 修复 PHP-7.4 下的兼容性 (@twose) (@matyhtf)
- 修复 HTTP-chunk 的长度解析错误问题 (19a1c712) (@twose)
- 修复 chunked 模式下 multipart 请求的解析器行为 (3692d9de) (@twose)
- 修复 PHP-Debug 模式下 ZEND_ASSUME 断言失败 (fc0982be) (@twose)
- 修复 Socket 错误的地址 (d72c5e3a) (@twose)
- 修复 Socket getname (#3177) (#3179) (@matyhtf)
- 修复静态文件处理器对于空文件的错误处理 (#3182) (@twose)
- 修复 Coroutine\Http\Server 上传文件问题 (#3189) (#3191) (@twose)
- 修复 shutdown 期间可能的内存错误 (44aef60a) (@matyhtf)
- 修复 Server->heartbeat (#3203) (@matyhtf)
- 修复 CPU 调度器可能无法调度死循环的情况 (#3207) (@twose)
- 修复在不可变数组上的无效写入操作 (#3212) (@twose)
- 修复 WaitGroup 多次 wait 问题 (swoole/library@537a82e1) (@twose)
- 修复空 header 的处理 (和 cURL 保持一致) (swoole/library@7c92ed5a) (@twose)
- 修复非 IO 方法返回 false 时抛出异常的问题 (swoole/library@f6997394) (@twose)
- 修复 cURL-hook 下使用 proxy 端口号被多次添加到标头的问题 (swoole/library@5e94e5da) (@twose)

## v4.4.16

[v4.4.16](https://github.com/swoole/swoole-src/releases/tag/v4.4.16)，这是一个 BUG 修复版本, 没有任何向下不兼容改动

### 增强

- 现在你可以获取 [Swoole 版本支持信息](https://github.com/swoole/swoole-src/blob/master/SUPPORTED.md)
- 更友好的错误提示 (0412f442) (09a48835) (@twose)
- 防止在某些特殊系统上陷入系统调用死循环 (069a0092) (@matyhtf)
- 在 PDOConfig 中增加驱动选项 (swoole/library#8) (@jcheron)

### 修复

- 修复 http2_session.default_ctx 内存错误 (bddbb9b1) (@twose)
- 修复未初始化的 http_context (ce77c641) (@twose)
- 修复 Table 模块中的书写错误 (可能会造成内存错误) (db4eec17) (@twose)
- 修复 Server 中 task-reload 的潜在问题 (e4378278) (@GXhua)
- 修复不完整协程 HTTP 服务器请求原文 (#3079) (#3085) (@hantaohuang)
- 修复 static handler (当文件为空时, 不应返回 404 响应) (#3084) (@Yurunsoft)
- 修复 http_compression_level 配置无法正常工作 (16f9274e) (@twose)
- 修复 Coroutine HTTP2 Server 由于没有注册 handle 而产生空指针错误 (ed680989) (@twose)
- 修复配置 socket_dontwait 不工作的问题 (27589376) (@matyhtf)
- 修复 zend::eval 可能会被执行多次的问题 (#3099) (@GXhua)
- 修复 HTTP2 服务器由于在连接关闭后响应而产生的空指针错误 (#3110) (@twose)
- 修复 PDOStatementProxy::setFetchMode 适配不当的问题 (swoole/library#13) (@jcheron)
