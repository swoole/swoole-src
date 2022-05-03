# 向下不兼容改动

## v4.8.0

- 在 base 模式下，onStart 回调将始终在第一个工作进程 (worker id 为 0) 启动时回调，先于 onWorkerStart 执行。在 onStart 函数中始终可以使用协程 API，Worker-0 出现致命错误重启时，会再次回调 onStart。  
在之前的版本中，onStart 在只有一个工作进程时，会在 Worker-0 中回调。有多个工作进程时，在 Manager 进程中执行。

## v4.7.0

- 移除了 `Table\Row`，`Table` 不再支持以数组的方式读写

## v4.6.0

- 移除了`session id`的最大限制，不再重复
- 使用协程时禁用不安全功能，包括`pcntl_fork`/`pcntl_wait`/`pcntl_waitpid`/`pcntl_sigtimedwait`
- 默认启用 coroutine hook
- 不再支持 PHP7.1
- 将 `Event::rshutdown()` 标记为已弃用，请改用 Coroutine\run

## v4.5.4

- `SWOOLE_HOOK_ALL` 包括 `SWOOLE_HOOK_CURL`
- 移除了`ssl_method`，支持`ssl_protocols`

## v4.4.12

- 该版本支持了WebSocket帧压缩，修改了push方法的第三个参数为flags，如未设置strict_types，代码兼容性不受影响，否则会出现bool无法隐式转换为int的类型错误，此问题将在v4.4.13修复

## v4.4.1

- 注册的信号不再作为维持事件循环的条件，**如程序只注册了信号而未进行其他工作将被视为空闲并随即退出** （此时可通过注册一个定时器防止进程退出）

## v4.4.0

- 和`PHP`官方保持一致, 不再支持`PHP7.0` (@matyhtf)
- 移除`Serialize`模块, 在单独的 [ext-serialize](https://github.com/swoole/ext-serialize) 扩展中维护
- 移除`PostgreSQL`模块，在单独的 [ext-postgresql](https://github.com/swoole/ext-postgresql) 扩展中维护
- `Runtime::enableCoroutine`不再会自动兼容协程内外环境, 一旦开启, 则一切阻塞操作必须在协程内调用 (@matyhtf)
- 由于引入了全新的协程`MySQL`客户端驱动, 底层设计更加规范, 但有一些小的向下不兼容的变化 (详见 [4.4.0更新日志](https://wiki.swoole.com/wiki/page/p-4.4.0.html))

## v4.3.0

- 移除了所有异步模块, 详见 [独立异步扩展](https://wiki.swoole.com/wiki/page/p-async_ext.html) 或  [4.3.0更新日志](https://wiki.swoole.com/wiki/page/p-4.3.0.html)

## v4.2.13

> 由于历史API设计存在问题导致的不可避免的不兼容变更

* 协程Redis客户端订阅模式操作变更, 详见[订阅模式](https://wiki.swoole.com/#/coroutine_client/redis?id=%e8%ae%a2%e9%98%85%e6%a8%a1%e5%bc%8f)

## v4.2.12

> 实验特性 + 由于历史API设计存在问题导致的不可避免的不兼容变更

- 移除了`task_async`配置项，替换为[task_enable_coroutine](https://wiki.swoole.com/#/server/setting?id=task_enable_coroutine)

## v4.2.5

- 移除了`onReceive`和`Server::getClientInfo`对`UDP`客户端的支持

## v4.2.0

- 彻底移除了异步`swoole_http2_client`, 请使用协程HTTP2客户端

## v4.0.4

此版本开始, 异步`Http2\Client` 将会触发 `E_DEPRECATED` 提示, 并在下个版本删除, 请使用 `Coroutine\Http2\Client`来代替

 `Http2\Response` 的 `body` 属性 重命名 为 `data`, 此修改是为了保证 `request` 和 `response` 两者的统一, 并且更符合HTTP2协议的帧类型名称

自该版本起, `Coroutine\Http2\Client` 拥有了相对完整的HTTP2协议支持, 能满足企业级的生产环境应用需求, 如`grpc`, `etcd` 等, 所以关于HTTP2的一系列改动是非常必要的

## v4.0.3

使 `swoole_http2_response` 和 `swoole_http2_request` 保持一致, 所有属性名修改为复数形式, 涉及以下属性

- `headers`
- `cookies`

## v4.0.2

> 由于底层实现过于复杂, 难以维护, 且用户经常对其使用产生误区,  故暂时删除以下API:

- `Coroutine\Channel::select`

但同时增加了`Coroutine\Channel->pop`方法的第二参数为`timeout`来满足开发需求

## v4.0

> 由于协程内核升级, 可以在任意函数任意地方调用协程, 无需做特殊处理, 故删除了以下API

- `Coroutine::call_user_func`
- `Coroutine::call_user_func_array`
