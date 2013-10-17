Swoole介绍
-----
Swoole是一个PHP的C扩展，可用来开发PHP的高性能高并发TCP/UDP Server。Swoole的网络IO部分基于epoll/kqueue事件循环，是全异步非阻塞的。 业务逻辑部分使用多进程同步阻塞方式来运行。这样既保证了Server能够应对高并发和大量TCP连接。又保证业务代码仍然可以简单的编写。

Swoole是开源免费的自由软件，授权协议是LGPL。企业和开发者均可免费使用Swoole的代码。

Swoole包含Server和Client 2个部分。名称为swoole_server_*的函数都是属于Server部分的。client部分以类的方式提供。  

* [编译安装](install.md)
* [环境依赖](dependency.md)
* [版本更新记录](project/change_log.md)
* [项目路线图](project/road_map.md)
* [提交错误报告](project/report.md)
* [内核参数调整](server/sysctl.md)
* [开发者列表](author.md)

Server
-----
* **函数列表**
    * [swoole_server_set参数说明](server/setting.md)
    * [swoole_server_create运行模式说明](factory_mode.md)
    * [swoole_server_addlisten多端口混合监听](addlisten.md)
    * [swoole_server_addtimer定时器的使用](timer.md)
    * [swoole_server_handler设置事件回调](event_handler.md)
    * [swoole_server_start函数启动Server](server/start.md)
    * [swoole_server_reload柔性终止/重启策略](server/reload.md)
    * [swoole_server_close函数关闭连接](server/close.md)
    * [swoole_server_send函数向客户端发送数据](server/send.md)
    * [swoole_connection_info获取连接信息](connection_info.md)
    * [swoole_connection_list遍历所有连接](connection_list.md)
    * [Swoole预定义常量](define.md)        
* **事件回调函数**  
    * [onStart](event/onStart.md)
    * [onShutdown](event/onShutdown.md)
    * [onWorkerStart](event/onWorkerStart.md)
    * [onWorkerStop](event/onWorkerStop.md)
    * [onTimer](event/onTimer.md)
    * [onConnect](event/onConnect.md)
    * [onReceive](event/onReceive.md)
    * [onClose](event/onClose.md)
    * [onMasterConnect](event/onMasterConnect.md)
    * [onMasterClose](event/onMasterClose.md)
    * [onEvent](event/onEvent.md)        
* **特性设置**
    * [改变Worker进程的用户/组](user.md)
    * [回调函数中的from_id和fd](fd.md)
    * [Buffer和EOF_Check的使用](buffer.md) 
    * [Worker与Reactor通信模式](dispatch_mod.md)
    * [TCP-Keepalive死连接检测](tcp_keepalive.md)        
* **示例程序**
    * [PHP](https://github.com/matyhtf/swoole/blob/master/examples/server.php)
    * [C/C++](https://github.com/matyhtf/swoole/blob/master/examples/server.c)    
* **压力测试**
    * [Nginx/Golang/Swoole/Node.js的性能对比](bench.md) 
    * [并发10万TCP连接的测试](c100k.md)

Client
-----
swoole的client部分提供了tcp/udp socket的类封装代码，使用时仅需 new swoole_client即可。
swoole的socket client对比PHP提供的stream族函数有哪些好处：

* stream函数存在超时设置的陷阱和Bug，一旦没处理好会导致Server端长时间阻塞
* fread有8192长度限制，无法支持UDP的大包
* swoole_client支持waitall，在知道包长度的情况下可以一次取完，不必循环取。
* swoole_client支持UDP connect，解决了UDP串包问题
* swoole_client是纯C的代码，专门处理socket，stream函数非常复杂。swoole_client性能更好  

-----
* **方法列表**
    * [swoole_client->__construct](client/construct.md)
    * [swoole_client->connect](client/connect.md)
    * [swoole_client->send](client/send.md)
    * [swoole_client->recv](client/recv.md)
    * [swoole_client->close](client/close.md)
* **属性列表**
    * [swoole_client->errCode](client/errCode.md)
    * [swoole_client->sock](client/sock.md)
* **并行**
    * [swoole_client_select函数](client/select.md)
    * [TCP客户端异步连接](client/async_connect.md)
* **示例程序**
    * [examples/client.php](https://github.com/matyhtf/swoole/blob/master/examples/client.php)


高级
-----
* [Swoole的实现](swoole.md)
* [Worker进程](worker.md)
* [C/C++开发者如何使用Swoole框架](use_c.md)
* [Swoole内存池的实现]
* [Swoole内存队列]
* [Swoole基于共享内存+eventfd实现的Channel]

其他
-----
* [Swoole社区](community.md)
