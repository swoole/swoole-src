Swoole介绍
-----
Swoole是一个PHP的C扩展，可用来开发PHP的高性能高并发TCP/UDP Server。Swoole的网络IO部分基于epoll/kqueue事件循环，是全异步非阻塞的。 业务逻辑部分使用多进程同步阻塞方式来运行。这样既保证了Server能够应对高并发和大量TCP连接。又保证业务代码仍然可以简单的编写。

Swoole包含Server和Client2个部分。名称为swoole_server_*的函数都是属于Server部分的。client部分以类的方式提供。  

* [编译安装](install.md)
* [环境依赖](dependency.md)

Server
-----
* [swoole_server_set参数说明](setting.md)
* [swoole_server_create运行模式说明](factory_mode.md)
* [swoole_server_handler设置事件回调](event_handler.md)
* swoole_server_close函数，用来关闭一个连接
* swoole_server_send函数，用于向客户端发送数据
* [swoole_server_reload柔性终止/重启策略](reload.md)
* swoole_server_start函数，启动Server
* [改变Worker进程的用户/组](user.md)
* [swoole_server_addlisten多端口混合监听](addlisten.md)
* [swoole_server_addtimer定时器的使用](timer.md)
* [swoole_connection_info获取连接信息](connection_info.md)
* [回调函数中的from_id和fd](fd.md)
* [Buffer和EOF_Check的使用](buffer.md) 
* [Worker与Reactor通信模式](dispatch_mod.md)
* [TCP-Keepalive死连接检测](tcp_keepalive.md)
* [Swoole预定义常量](define.md)
* [Nginx/Golang/Swoole/Node.js的性能对比](bench.md) 
* [并发10万TCP连接的测试](c100k.md)

Client
-----
swoole的client部分提供了tcp/udp socket的类封装代码，使用时仅需 new swoole_client即可。
swoole的socket client对比PHP提供的stream有哪些好处：

* stream函数存在超时设置的陷阱和Bug，一旦没处理好会导致Server端长时间阻塞
* fread有8192长度限制，无法支持UDP的大包
* swoole_client支持waitall，在知道包长度的情况下可以一次取完，不必循环取。
* swoole_client支持UDP connect，解决了UDP串包问题
* swoole_client是纯C的代码，专门处理socket，stream函数非常复杂。swoole_client性能更好

详情参看examples/client.php中的代码。

client可以并行。swoole_client中用了select来做IO事件循环。为什么要用select呢？因为client一般不会有太多连接，而且大部分socket会很快接收到响应数据。  

在少量连接的情况下select比epoll性能更好。另外select更简单。

* [查看示例代码 client.php](https://github.com/matyhtf/swoole/blob/master/examples/client.php)

高级
-----
* [Swoole的实现](swoole.md)
* [Worker进程](worker.md)
* [C/C++开发者如何使用Swoole框架](use_c.md)

其他
-----
* [Swoole社区](community.md)
