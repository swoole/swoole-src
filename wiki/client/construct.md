swoole_client->__construct构造函数
-----
函数原型：
```php
swoole_client->__construct(int $sock_type, int $is_sync = SWOOLE_SOCK_SYNC);
```
可以使用swoole提供的宏来之指定类型，请参考 [swoole常量定义](define.md)  
$sock_type表示socket的类型，如TCP/UDP。  
$is_sync表示同步还是异步
> 暂时不支持异步写法  
> swoole_client在unset时会自动调用close方法关闭socket。

