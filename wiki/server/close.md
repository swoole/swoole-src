swoole_server_close函数
-----
关闭客户端连接，函数原型：
```php
bool swoole_server_close(resource $serv, int $fd, int $from_id = 0);
```
> swoole-1.6以上版本不需要$from_id
> swoole-1.5.8以下的版本，务必要传入正确的$from_id，否则可能会导致连接泄露

操作成功返回true，失败返回false.  
Server主动close连接，也一样会触发onClose事件。不要在close之后写清理逻辑。应当放置到onClose回调中处理。
