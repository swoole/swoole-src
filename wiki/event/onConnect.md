onConnect
----
有新的连接进入时，在worker进程中回调。函数原型：
```php
void onConnect(resource $server, int $fd, int $from_id);
```

* $server是swoole的资源对象
* $fd是连接的文件描述符，发送数据/关闭连接时需要此参数
* $from_id来自那个poll线程

> onConnect/onClose这2个回调发生在worker进程内，而不是主进程。  
> 如果需要在主进程处理连接/关闭事件，请注册onMasterConnect/onMasterClose回调  
> onMasterConnect/onMasterClose回调总是先于onConnect/onClose被执行  

