onClose
----
连接关闭时在worker进程中回调。函数原型：
```php
void onClose(resource $server, int $fd, int $from_id);
```
* $server是swoole的资源对象
* $fd是连接的文件描述符
* $from_id来自那个poll线程

> 无论close由客户端发起还是服务器端主动调用swoole_server_close关闭连接，都会触发此事件   
> 因此只要连接关闭，就一定会回调此函数

 