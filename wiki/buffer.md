Buffer和EOF_Check的使用
-----
在外网通信时，有些客户端发送数据的速度较慢，每次只能发送一小段数据。这样onReceive到的数据就不是一个完整的包。
还有些客户端是逐字节发送数据的，如果每次回调onReceive会拖慢整个系统。
Swoole提供了buffer和eof_check的功能，在C扩展底层检测到如果不是完整的请求，会等待新的数据到达，组成完成的请求后再回调onReceive。

在swoole_server_set中增加，open_eof_check和data_eof来开启此功能。open_eof_check=1表示启用buffer检查，data_eof设置数据包结束符。

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
    'data_eof' => "\r\n\r\n",  //http协议就是以\r\n\r\n作为结束符的，这里也可以使用二进制内容
    'open_eof_check' => 1,
));
```
