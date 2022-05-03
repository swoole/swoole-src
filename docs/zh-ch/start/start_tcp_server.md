# TCP 服务器

## 程序代码

server.php

```php
//创建Server对象，监听 127.0.0.1:9501 端口
$server = new Swoole\Server('127.0.0.1', 9501);

//监听连接进入事件
$server->on('Connect', function ($server, $fd) {
    echo "Client: Connect.\n";
});

//监听数据接收事件
$server->on('Receive', function ($server, $fd, $reactor_id, $data) {
    $server->send($fd, "Server: {$data}");
});

//监听连接关闭事件
$server->on('Close', function ($server, $fd) {
    echo "Client: Close.\n";
});

//启动服务器
$server->start(); 
```

这样就创建了一个`TCP`服务器，监听本机`9501`端口。它的逻辑很简单，当客户端`Socket`通过网络发送一个 `hello` 字符串时，服务器会回复一个 `Server: hello` 字符串。

`Server`是异步服务器，所以是通过监听事件的方式来编写程序的。当对应的事件发生时底层会主动回调指定的函数。如当有新的`TCP`连接进入时会执行[onConnect](/server/events?id=onconnect)事件回调，当某个连接向服务器发送数据时会回调[onReceive](/server/events?id=onreceive)函数。

* 服务器可以同时被成千上万个客户端连接，`$fd`就是客户端连接的唯一标识符
* 调用 `$server->send()` 方法向客户端连接发送数据，参数就是`$fd`客户端标识符
* 调用 `$server->close()` 方法可以强制关闭某个客户端连接
* 客户端可能会主动断开连接，此时会触发[onClose](/server/events?id=onclose)事件回调

## 执行程序

```shell
php server.php
```

在命令行下运行`server.php`程序，启动成功后可以使用 `netstat` 工具看到已经在监听`9501`端口。

这时就可以使用`telnet/netcat`工具连接服务器。

```shell
telnet 127.0.0.1 9501
hello
Server: hello
```

## 无法连接到服务器的简单检测手段

* 在`Linux`下，使用`netstat -an | grep 端口`，查看端口是否已经被打开处于`Listening`状态
* 上一步确认后，再检查防火墙问题
* 注意服务器所使用的IP地址，如果是`127.0.0.1`回环地址，则客户端只能使用`127.0.0.1`才能连接上
* 用的阿里云服务或者腾讯服务，需要在安全权限组进行设置开发的端口

## TCP数据包边界问题

参考[TCP数据包边界问题](/learn?id=tcp数据包边界问题)
