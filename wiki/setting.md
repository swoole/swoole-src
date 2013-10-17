swoole_server_set 参数说明
===========

示例：
```php
swoole_server_set($serv, array(
    'timeout' => 2.5,  //select and epoll_wait timeout. 
    'poll_thread_num' => 2, //reactor thread num
    'writer_num' => 2,      //writer thread num
    'worker_num' => 4,      //worker process num
    'backlog' => 128,       //listen backlog
    'max_request' => 50,
    'dispatch_mode' => 1, 
));
```

最大连接
-----
max_conn => 10000, 此参数用来设置Server最大允许维持多少个tcp连接。超过此数量后，新进入的连接将被拒绝。  

> 此参数不要调整的过大，根据机器内存的实际情况来设置。Swoole会根据此数值一次性分配一块大内存来保存Connection信息

守护进程化
-----
daemonize => 1，加入此参数后，执行php server.php将转入后台作为守护进程运行

poll线程数
-----
poll_thread_num => 2，通过此参数来调节poll线程的数量，以充分利用多核

Writer线程数
-----
writer_num => 2，通过此参数来调节Write线程的数量，以充分利用多核。在Swoole里对SOCKET的读写是分开的，IO_Read在reactor线程中完成，IO_Write在writer线程中完成

worker进程数
-----
worker_num =>4，设置启动的worker进程数量。swoole采用固定worker进程的模式。

max_request
-----
max_request => 2000，此参数表示worker进程在处理完n次请求后结束运行。manager会重新创建一个worker进程。此选项用来防止worker进程内存溢出
> 这里是按照onReceive回调执行次数计算的，onConnect/onClose不会增加计数  
> worker进程遇到致命错误也会退出，这里可以增加register_shutdown_function来做一定的清理工作  

Listen队列长度
-----
backlog => 128，此参数将决定最多同时有多少个待accept的连接，swoole本身accept效率是很高的，基本上不会出现大量排队情况。

CPU亲和设置
-----
open_cpu_affinity => 1 ,启用CPU亲和设置

TCP_NoDelay启用
-----
open_tcp_nodelay  => 1 ,启用tcp_nodelay

日志文件路径
-----
log_file => '/data/log/swoole.log', 指定swoole错误日志文件。在swoole运行期发生的异常信息会记录到这个文件中。默认会打印到屏幕。
> 此配置仅在swoole-1.5.8以上版本中可用

其他
-----
dispatch_mode  = 1 //1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配 不配置此参数，默认是取模

