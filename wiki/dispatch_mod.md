Worker与Reactor通信模式
=====
worker进程如何与reactor进程通信，Swoole提供了5种方式。通过swoole_server_setopt参数中修改dispatch_mode的值来配置。

轮询模式：dispatch_mode = 1
-----
收到的请求数据包会轮询发到每个Worker进程。

FD取模：dispatch_mode = 2(默认）
-----
数据包根据fd的值%worker_num来分配，这个模式可以保证同一个TCP客户端连接发送的数据总是会被分配给同一个worker进程。
这种模式可能会存在性能问题，作为SOA服务器时，不应当使用此模式。因为客户端很可能用了连接池，客户端100个进程复用10个连接，也就是同时只有10个swoole worker进程在处理请求。这种模式的业务系统可以使用dispatch_mode = 3，抢占式分配。

Queue模式：dispatch_mode = 3
-----
此模式下，网络请求的处理是抢占式的，这可以保证总是最空闲的worker进程才会拿到请求去处理。
这个模式的缺点是，客户端连接对应的worker是随机的。不确定哪个worker会处理请求。无法保存连接状态。
当然也可以借助第三方库来实现保存连接状态和会话内容，比如apc/redis/memcache。

ip取模：dispatch_mode = 4 
-----
(需1.7.7版本以上(不包括1.7.7)) 数据包根据ip的值%worker_num来分配，这个模式可以保证同一个ip的客户端连接发送的数据总是会被分配给同一个worker进程。

自定义uid取模：dispatch_mode = 5
-----
(1.7.7版本以上(不包括1.7.7)) 此模式在没有调用bind_uid之前，采用fd取模进行worker分配，调用$serv->bind_uid($uid)之后，会按照uid%worker_num取模进行分配。此模式有助于用户数据在worker进程中进行缓存，而不随用户上下线而变化。


