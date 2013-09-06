关于from_id和fd
-----
回调函数中经常看到它。  

* from_id是来自于哪个reactor线程
* fd是tcp连接的文件描述符

调用swoole_server_send/swoole_server_close函数需要传入这两个参数才能被正确的处理。如果业务中需要发送广播，需要将fd和from_id保存起来，可以用apc/redis/memcache来保存它。

> 新版的swoole[>=1.6.0]不再需要from_id参数，swoole本身提供了ConnectionList可以查询到当前所有的fd和对应from_id

```php
function my_onReceive($serv, $fd, $from_id, $data)  {
    //向当前fd发送数据，不需要填from_id
    swoole_server_send($serv, $fd, 'Swoole: '.$data); 

    //向某个Connection发送数据
    swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id); 

    //关闭当前Connection，不需要填from_id
    swoole_server_close($serv, $fd, $from_id); 

    //关闭任意Connection，需要from_id，否则会造成连接泄露
    swoole_server_close($serv, $ohter_fd, $other_from_id);
}
```


