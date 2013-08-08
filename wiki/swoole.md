Swoole的实现
=====
swoole使用纯C编写，不依赖其他第三方库。swoole并没有用libevent，所以不需要安装libevent。

socket部分
-----
swoole使用底层的socket系统调用。参见 sys/socket.h

IO事件循环
-----
主进程的事件循环使用select，poll线程中使用epoll/kqueue。

多进程/多线程
-----
多进程使用fork()系统调用
多线程使用pthread线程库

