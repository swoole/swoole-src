Server端部分
-----
* [swoole扩展编译安装](install.md)
* [swoole_server_set参数说明](setting.md)
* [swoole_server_create运行模式说明](factory_mode.md)
* swoole_server_close函数，用来关闭一个连接
* swoole_server_send函数，用于向客户端发送数据
* [swoole_server_addlisten多端口混合监听](addlisten.md)
* [swoole_server_addtimer定时器的使用](timer.md)
* 关于from_id和fd，回调函数中经常看到它。from_id是来自于哪个poll线程，fd是tcp连接的文件描述符。

Client端部分
-----
swoole的client部分提供了类的封装代码，使用时仅需 new swoole_client即可。
详情参看examples/client.php中的代码。

client可以并行。swoole_client中用了select来做IO事件循环。为什么要用select呢？因为client一般不会有太多连接的。
在少量连接的情况下select比epoll性能更好。另外select更简单。

高级
-----
* [Swoole的实现](swoole.md)
* [使用C代码开发](use_c.md)

其他
-----
* [Swoole社区](community.md)

