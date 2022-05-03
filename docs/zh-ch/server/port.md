# 多端口监听

`Server`可以监听多个端口，每个端口都可以设置不同的协议处理方式，例如80端口处理HTTP协议，9507端口处理TCP协议。`SSL/TLS`传输加密也可以只对特定的端口启用。

!> 例如主服务器是WebSocket或HTTP协议，新监听的TCP端口（[listen](/server/methods?id=listen)的返回值，即`Swoole\Server\Port`对象，以下简称port）默认会继承主Server的协议设置，必须单独调用`port`对象的`set`方法和`on`方法设置新的协议才会启用新协议。`port`对象的`set`和`on`方法，使用方法与基类[Swoole\Server](/server/init)完全一致。

## 监听新端口

```php
//返回port对象
$port1 = $server->listen("127.0.0.1", 9501, SWOOLE_SOCK_TCP);
$port2 = $server->listen("127.0.0.1", 9502, SWOOLE_SOCK_UDP);
$port3 = $server->listen("127.0.0.1", 9503, SWOOLE_SOCK_TCP | SWOOLE_SSL);
```

## 设置网络协议

```php
//port对象的调用set方法
$port1->set([
	'open_length_check' => true,
	'package_length_type' => 'N',
	'package_length_offset' => 0,
	'package_max_length' => 800000,
]);

$port3->set([
	'open_eof_split' => true,
	'package_eof' => "\r\n",
	'ssl_cert_file' => 'ssl.cert',
	'ssl_key_file' => 'ssl.key',
]);
```

## 设置回调函数

```php
//设置每个port的回调函数
$port1->on('connect', function ($serv, $fd){
    echo "Client:Connect.\n";
});

$port1->on('receive', function ($serv, $fd, $reactor_id, $data) {
    $serv->send($fd, 'Swoole: '.$data);
    $serv->close($fd);
});

$port1->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});

$port2->on('packet', function ($serv, $data, $addr) {
    var_dump($data, $addr);
});
```

## Http/WebSocket

`Swoole\Http\Server`和`Swoole\WebSocket\Server`因为是使用继承子类实现的，无法通过调用`Swoole\Server`实例的`listen`来方法创建HTTP或者WebSocket服务器。

如服务器的主要功能为`RPC`，但希望提供一个简单的Web管理界面。在这样的场景中，可以先创建`HTTP/WebSocket`服务器，然后再进行`listen`监听原生TCP的端口。

### 示例

```php
$http_server = new Swoole\Http\Server('0.0.0.0',9998);
$http_server->set(['daemonize'=> false]);
$http_server->on('request', function ($request, $response) {
    $response->header("Content-Type", "text/html; charset=utf-8");
    $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});

//多监听一个TCP端口，对外开启TCP服务，并设置TCP服务器的回调
$tcp_server = $http_server->listen('0.0.0.0', 9999, SWOOLE_SOCK_TCP);
//默认新监听的端口 9999 会继承主服务器的设置，也是 HTTP 协议
//需要调用 set 方法覆盖主服务器的设置
$tcp_server->set([]);
$tcp_server->on('receive', function ($server, $fd, $threadId, $data) {
    echo $data;
});

$http_server->start();
```

通过这样的代码，就可以建立一个对外提供HTTP服务，又同时对外提供TCP服务的Server，更加具体的优雅代码组合则由你自己来实现。

## TCP、HTTP、WebSocket多协议端口复合设置

```php
$port1 = $server->listen("127.0.0.1", 9501, SWOOLE_SOCK_TCP);
$port1->set([
    'open_websocket_protocol' => true, // 设置使得这个端口支持WebSocket协议
]);
```

```php
$port1 = $server->listen("127.0.0.1", 9501, SWOOLE_SOCK_TCP);
$port1->set([
    'open_http_protocol' => false, // 设置这个端口关闭HTTP协议功能
]);
```

同理还有：`open_http_protocol`、`open_http2_protocol`、`open_mqtt_protocol` 等参数

## 可选参数

* 监听端口`port`未调用`set`方法，设置协议处理选项的监听端口，将会继承主服务器的相关配置
* 主服务器为`HTTP/WebSocket`服务器，如果未设置协议参数，监听的端口仍然会设置为`HTTP`或`WebSocket`协议，并且不会执行为端口设置的[onReceive](/server/events?id=onreceive)回调
* 主服务器为`HTTP/WebSocket`服务器，监听端口调用`set`设置配置参数，会清除主服务器的协议设定。监听端口将变为`TCP`协议。监听的端口如果希望仍然使用`HTTP/WebSocket`协议，需要在配置中增加`open_http_protocol => true` 和 `open_websocket_protocol => true`

**`port`可以通过`set`设置的参数有：**

* socket参数：如`backlog`、`open_tcp_keepalive`、`open_tcp_nodelay`、`tcp_defer_accept`等
* 协议相关：如`open_length_check`、`open_eof_check`、`package_length_type`等
* SSL证书相关：如`ssl_cert_file`、`ssl_key_file`等

具体可参考[配置章节](/server/setting)

## 可选回调

`port`未调用`on`方法，设置回调函数的监听端口，默认使用主服务器的回调函数，`port`可以通过`on`方法设置的回调有：
 
### TCP服务器

* onConnect
* onClose
* onReceive

### UDP服务器

* onPacket
* onReceive
    
### HTTP服务器

* onRequest
    
### WebSocket服务器

* onMessage
* onOpen
* onHandshake

!> 不同监听端口的回调函数，仍然是相同的`Worker`进程空间内执行

## 多端口下的连接遍历

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9514, SWOOLE_BASE);

$tcp = $server->listen("0.0.0.0", 9515, SWOOLE_SOCK_TCP);
$tcp->set([]);

$server->on("open", function ($serv, $req) {
    echo "new WebSocket Client, fd={$req->fd}\n";
});

$server->on("message", function ($serv, $frame) {
    echo "receive from {$frame->fd}:{$frame->data},opcode:{$frame->opcode},fin:{$frame->finish}\n";
    $serv->push($frame->fd, "this is server OnMessage");
});

$tcp->on('receive', function ($server, $fd, $reactor_id, $data) {
    //仅遍历 9514 端口的连接，因为是用的$server，不是$tcp
    $websocket = $server->ports[0];
    foreach ($websocket->connections as $_fd) {
        var_dump($_fd);
        if ($server->exist($_fd)) {
            $server->push($_fd, "this is server onReceive");
        }
    }
    $server->send($fd, 'receive: '.$data);
});

$server->start();
```
