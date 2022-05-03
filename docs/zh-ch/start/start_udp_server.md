# UDP 服务器

## 程序代码

udp_server.php

```php
$server = new Swoole\Server('127.0.0.1', 9502, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

//监听数据接收事件
$server->on('Packet', function ($server, $data, $clientInfo) {
    var_dump($clientInfo);
    $server->sendto($clientInfo['address'], $clientInfo['port'], "Server：{$data}");
});

//启动服务器
$server->start();
```

UDP服务器与TCP服务器不同，UDP没有连接的概念。启动Server后，客户端无需Connect，直接可以向Server监听的9502端口发送数据包。对应的事件为onPacket。

* `$clientInfo`是客户端的相关信息，是一个数组，有客户端的IP和端口等内容
* 调用 `$server->sendto` 方法向客户端发送数据

## 启动服务

```shell
php udp_server.php
```

UDP服务器可以使用 `netcat -u` 来连接测试

```shell
netcat -u 127.0.0.1 9502
hello
Server: hello
```
