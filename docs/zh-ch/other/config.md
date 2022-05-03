# ini配置

配置 | 默认值 | 作用
---|---|---
swoole.enable_coroutine | On | `On`, `Off` 开关内置协程，[详见](/server/setting?id=enable_coroutine)。
swoole.display_errors | On | 开启/关闭`Swoole`错误信息。
swoole.unixsock_buffer_size | 8M | 设置进程间通信的`Socket`缓存区尺寸，等价于[socket_buffer_size](/server/setting?id=socket_buffer_size)。
swoole.use_shortname | On | 是否启用短别名，[详见](/other/alias?id=协程短名称)。
swoole.enable_preemptive_scheduler | Off | 可防止某些协程死循环占用CPU时间过长(10ms的CPU时间)导致其它协程得不到[调度](/coroutine?id=协程调度)，[示例](https://github.com/swoole/swoole-src/tree/master/tests/swoole_coroutine_scheduler/preemptive)。
swoole.enable_library | On | 开启/关闭扩展内置的library
