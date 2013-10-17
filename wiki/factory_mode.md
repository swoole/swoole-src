swoole_server_create运行模式说明
=====
创建一个swoole server资源对象。函数原型：
```php
int swoole_server_create(string $host, int $port, int $mode = SWOOLE_PROCESS,
    int $sock_type = SWOOLE_SOCK_TCP);
```
* $host参数用来指定监听的ip地址，如127.0.0.1，或者外网地址，或者0.0.0.0监听全部地址
* $port监听的端口，如9501，监听小于1024端口需要root权限，如果此端口被占用server-start时会失败
* $mode运行的模式，swoole提供了3种运行模式，默认为多进程模式
* $sock_type指定socket的类型，支持TCP/UDP、TCP6/UDP64种

> Swoole1.6版本之后PHP版本将去掉Base/线程2个模式，原因是php的内存管理器在多线程下容易发生错误  
> Base模式和线程模式仅供C++中使用

运行模式的说明：

一、Base模式
-----
这种模式就是传统的异步非阻塞Server了。在Reactor线程内直接回调PHP的函数。
这个模式适合业务逻辑简单，并且onReceive中没有读文件、读取数据库、请求网络以及其他阻塞操作的场景。
WebIM、Proxy、TimeServer、Memcached等就可以使用Base模式来运行，简单高效。
在Swoole里还可以开多个线程，实现Multi Reactor，以充分利用多核。

二、线程模式
-----
这个就是多线程Worker模式，Reactor线程来处理网络事件轮询，读取数据。得到的请求交给Worker线程去处理。
Swoole提供了可配置的参数，以实现m/n的参数调整。在这种模式下onReceive可以有适度的阻塞操作。多线程模式比进程模式轻量一些，而且线程之间可以共享堆栈和资源。
访问共享内存时会有同步问题，需要使用Swoole提供的锁机制来保护数据。目前已经提供了Mutex、读写锁、文件锁、信号量、自旋锁一共5种锁的实现。

三、进程模式
-----
多进程模式是最复杂的方式，用了大量的进程间通信、进程管理机制。适合业务逻辑非常复杂的场景。Swoole提供了完善的进程管理、内存保护机制。
在业务逻辑非常复杂的情况下，也可以长期稳定运行。

Swoole在Reactor线程中提供了Buffer的功能，可以应对大量慢速连接和逐字节的恶意客户端。另外也提供了CPU亲和设置选项，使程序运行的效率更好。