swoole_connection_info获取连接信息
-----
swoole_connection_info函数用来获取连接的信息
> 需要swoole-1.5.8以上版本
* 如果传入的fd存在，将会返回一个数组
* 连接不存在或已关闭，返回false

```php
$fdinfo = swoole_connection_info($serv, $fd);
var_dump($fdinfo);
array(5) {
  ["from_id"]=>
  int(3)
  ["from_fd"]=>
  int(14)
  ["from_port"]=>
  int(9501)
  ["remote_port"]=>
  int(19889)
  ["remote_ip"]=>
  string(9) "127.0.0.1"
}
```

__from_id__ 来自哪个poll线程
_from_fd_ 来自哪个server socket
_from_port_   来自哪个端口


