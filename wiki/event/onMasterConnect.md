onMasterConnect
----
当连接被关闭时，回调此函数。与onConnect相同。onMasterConnect/onMasterClose都是在主进程中执行的。

```php
void onMasterConnect(resource $server, int $fd, int $from_id);
```

> 此回调函数中不要有阻塞操作，否则会导致服务器端无法及时Accept新的连接  
> 由于是在不同的进程空间内，onMasterConnect/onMasterClose对全局变量的修改在worker进程中是无效的  
