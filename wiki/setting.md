swoole_server_set 参数说明
===========

示例：
```php
swoole_server_set($serv, array(
    'timeout' => 2.5,  //select and epoll_wait timeout. 
    'poll_thread_num' => 2, //reactor thread num
    'writer_num' => 2,     //writer thread num
    'worker_num' => 4,    //worker process num
    'backlog' => 128,   //listen backlog
    'max_request' => 50,
    'dispatch_mode'=>1, 
));
```

Daemonize守护进程化
-----
daemonize => 1，加入此参数后，执行php server.php将转入后台作为守护进程运行

Reactor线程数
-----
poll_thread_num => 2，通过此参数来调节Reactor线程的数量，以充分利用多核

Writer线程数
-----
writer_num => 2，通过此参数来调节Write线程的数量，以充分利用多核。在Swoole里对SOCKET的读写是分开的，IO_Read在reactor线程中完成，IO_Write在writer线程中完成

Listen队列长度
-----
backlog => 128，此参数将决定最多同时有多少个待accept的连接，swoole本身accept效率是很高的，基本上不会出现大量排队情况。

其他
-----
open_cpu_affinity => 1 ,启用CPU亲和设置
open_tcp_nodelay  => 1 ,启用tcp_nodelay
dispatch_mode  = 1 //1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配 不配置此参数，默认是取模

