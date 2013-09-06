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

* __from_id__ 来自哪个poll线程
* __from_fd__ 来自哪个server socket
* __from_port__ 来自哪个Server端口
* __remote_port__ 客户端连接的端口
* __remote_ip__ 客户端连接的ip


