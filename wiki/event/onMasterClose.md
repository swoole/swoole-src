onMasterClose
----
当连接被关闭时，回调此函数。与onClose相同。onMasterConnect/onMasterClose都是在主进程中执行的。

```php
void onMasterClose(resource $server, int $fd, int $from_id);
```

> 此回调函数中不要有阻塞操作，否则会导致服务器端无法及时Accept新的连接
