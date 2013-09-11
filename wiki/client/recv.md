swoole_client->recv接收数据
-----
recv方法用于从服务器端接收数据。接受2个参数。函数原型为：
```php
string $swoole_client->recv(int $size = 65535, bool $waitall = 0);
```

* $size：接收数据的最大长度  
* $waitall: 是否等待所有数据到达后返回

> 如果设定了$waitall就必须设定准确的$size，否则会一直等待，直到接收的数据长度达到$size  
> 如果设置了错误的$size，会导致recv超时，返回 **false**

调用成功返回结果字符串，失败返回 **false**，并设置$swoole_client->errCode属性