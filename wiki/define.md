Swoole预定义常量
=====

swoole_server_create()参数
-----
* *SWOOLE_BASE* 使用Base模式，业务代码在Reactor中直接执行
* *SWOOLE_THREAD* 使用线程模式，业务代码在Worker线程中执行
* *SWOOLE_PROCESS* 使用进程模式，业务代码在Worker进程中执行

new swoole_client()构造函数参数
-----
* *SWOOLE_SOCK_TCP* 创建tcp socket 
* *SWOOLE_SOCK_TCP6* 创建tcp ipv6 socket
* *SWOOLE_SOCK_UDP* 创建udp socket
* *SWOOLE_SOCK_UDP6* 创建udp ipv6 socket  
* *SWOOLE_SOCK_SYNC* 同步客户端
* *SWOOLE_SOCK_ASYNC* 异步客户端

