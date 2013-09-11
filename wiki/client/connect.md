swoole_client->connect连接到远程服务器
-----
函数原型：
```php
bool $swoole_client->connect(string $host, int $port, float $timeout = 0.1, int $flag = 0)
```
connect方法接受4个参数：

* $host是远程服务器的地址
* $port是远程服务器端口
* $timeout是网络IO的超时，单位是s，支持浮点数。默认为0.1s，即100ms
* $flag参数在UDP类型时表示是否启用udp_connect  
设定此选项后将绑定$host与$port，此UDP将会丢弃非指定host/port的数据包。
* $flag参数在TCP类型,$flag=1表示设置为非阻塞socket，connect会立即返回。  
在send/recv前必须使用swoole_client_select来检测是否完成了连接
    
