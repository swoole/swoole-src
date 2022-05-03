# Library

Swoole 在 v4 版本后内置了 [Library](https://github.com/swoole/library) 模块，**使用 PHP 代码编写内核功能**，使得底层设施更加稳定可靠

!> 该模块也可通过 composer 单独安装，单独安装使用时需要通过`php.ini`配置`swoole.enable_library=Off`关闭扩展内置的 library

目前提供了以下工具组件：

- [Coroutine\WaitGroup](https://github.com/swoole/library/blob/master/src/core/Coroutine/WaitGroup.php) 用于等待并发协程任务，[文档](/coroutine/wait_group)
- [Coroutine\FastCGI](https://github.com/swoole/library/tree/master/src/core/Coroutine/FastCGI) FastCGI 客户端，[文档](/coroutine_client/fastcgi)
- [Coroutine\Server](https://github.com/swoole/library/blob/master/src/core/Coroutine/Server.php) 协程 Server，[文档](/coroutine/server)
- [Coroutine\Barrier](https://github.com/swoole/library/blob/master/src/core/Coroutine/Barrier.php) 协程屏障，[文档](/coroutine/barrier)

- [CURL hook](https://github.com/swoole/library/tree/master/src/core/Curl) CURL 协程化，[文档](/runtime?id=swoole_hook_curl)
- [Database](https://github.com/swoole/library/tree/master/src/core/Database) 各种数据库连接池和对象代理的高级封装，[文档](/coroutine/conn_pool?id=database)
- [ConnectionPool](https://github.com/swoole/library/blob/master/src/core/ConnectionPool.php) 原始连接池，[文档](/coroutine/conn_pool?id=connectionpool)
- [Process\Manager](https://github.com/swoole/library/blob/master/src/core/Process/Manager.php) 进程管理器，[文档](/process/process_manager)

- [StringObject](https://github.com/swoole/library/blob/master/src/core/StringObject.php) 、[ArrayObject](https://github.com/swoole/library/blob/master/src/core/ArrayObject.php) 、[MultibyteStringObject](https://github.com/swoole/library/blob/master/src/core/MultibyteStringObject.php) 面向对象风格的 Array 和 String 编程

- [functions](https://github.com/swoole/library/blob/master/src/core/Coroutine/functions.php) 提供的一些协程函数，[文档](/coroutine/coroutine?id=函数)
- [Constant](https://github.com/swoole/library/tree/master/src/core/Constant.php) 常用配置常量
- [HTTP Status](https://github.com/swoole/library/blob/master/src/core/Http/Status.php) HTTP 状态码

## 示例代码

[Examples](https://github.com/swoole/library/tree/master/examples)
