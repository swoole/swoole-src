Swoole预定义常量
-----

* swoole_server_create()参数
    * **SWOOLE_BASE** 使用Base模式，业务代码在Reactor中直接执行
    * **SWOOLE_THREAD** 使用线程模式，业务代码在Worker线程中执行
    * **SWOOLE_PROCESS** 使用进程模式，业务代码在Worker进程中执行

* new swoole_client()构造函数参数
    * __SWOOLE_SOCK_TCP__ 创建tcp socket 
    * __SWOOLE_SOCK_TCP6__ 创建tcp ipv6 socket
    * __SWOOLE_SOCK_UDP__ 创建udp socket
    * __SWOOLE_SOCK_UDP6__ 创建udp ipv6 socket  
    * __SWOOLE_SOCK_SYNC__ 同步客户端
    * __SWOOLE_SOCK_ASYNC__ 异步客户端

