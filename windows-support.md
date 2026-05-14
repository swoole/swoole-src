将在 6.3 版本提供，区别于 Cygwin 版本，6.3 将提供原生的 Windows 支持。但由于 `Windows` 与 `Linux` 的差异较大，一些模块在原生`Windows`版本中将不再提供。

## Windows 不支持的内核特性

- `UnixSocket`
- `fork`，Windows 下的 CreateProcess 与 fork 完全不同，无法继承父进程的资源，不支持 COW
- `Signal`, Windows 对信号的支持不完整


## Windows 下不支持的模块

- `Server`：不支持异步 Server，异步 Server 大量使用了 fork 进程、UnixSocket ，这些在 Windows 都无法实现，在 Windows 下只能使用协程 Server
- `Process`：不支持创建子进程
- `Process\Pool`：不支持
- `MsgQueue`：不支持
- `Reactor`：不支持，`Event` 相关 `API` 不可用
- `Async\Client`：不支持，仅支持协程客户端


## Windows 原生异步
- 完全基于 `IOCP` 实现异步 `IO` 和协程机制
- 支持多线程模块，需要`PHP ZTS`，但不支持`IOCP`的多线程负载均衡机制，每个线程必须创建单独的`IOCP`句柄
- 定时器，基于`TimerQueue`


## 工作进度（已完成）
1. Swoole\Server 以及相关的子类 Swoole\Http\Server、Swoole\WebSocket\Server、Swoole\Redis\Server、AdminServer 相关的源文件和目录直接排除
2. 编写了 src\os\win32.cc 和 swoole_win32.h 头文件，实现适配
3. 进程相关的文件排除，包括 Swoole\Process、Swoole\Process\Pool，以及 wait.cc、swoole_fork 等函数
4. 管道和 unixsocket 相关代码排除
5. Reactor 相关文件已排除

> 配置文件是 config.w32

## 待进行

1. Swoole\Event 也应该排除，Windows 使用 IOCP ，不需要 Reactor 模块
2. IOCP 与 Iouring 相似，应参考 uring-socket 的方式实现，对照 Swoole\Coroutine\Socket 相关的代码
3. 需要支持 SSL
4. Swoole\Coroutine 相关的特性要全部支持