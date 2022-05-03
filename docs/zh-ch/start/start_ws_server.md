# WebSocket服务器

## 程序代码

ws_server.php
```php
//创建WebSocket Server对象，监听0.0.0.0:9502端口
$ws = new Swoole\WebSocket\Server('0.0.0.0', 9502);

//监听WebSocket连接打开事件
$ws->on('Open', function ($ws, $request) {
    $ws->push($request->fd, "hello, welcome\n");
});

//监听WebSocket消息事件
$ws->on('Message', function ($ws, $frame) {
    echo "Message: {$frame->data}\n";
    $ws->push($frame->fd, "server: {$frame->data}");
});

//监听WebSocket连接关闭事件
$ws->on('Close', function ($ws, $fd) {
    echo "client-{$fd} is closed\n";
});

$ws->start();
```

* 客户端向服务器端发送信息时，服务器端触发`onMessage`事件回调
* 服务器端可以调用`$server->push()`向某个客户端（使用$fd标识符）发送消息

## 运行程序

```shell
php ws_server.php
```

可以使用Chrome浏览器进行测试，JS代码为：

```javascript
var wsServer = 'ws://127.0.0.1:9502';
var websocket = new WebSocket(wsServer);
websocket.onopen = function (evt) {
	console.log("Connected to WebSocket server.");
};

websocket.onclose = function (evt) {
	console.log("Disconnected");
};

websocket.onmessage = function (evt) {
	console.log('Retrieved data from server: ' + evt.data);
};

websocket.onerror = function (evt, e) {
	console.log('Error occured: ' + evt.data);
};
```

## Comet

WebSocket服务器除了提供WebSocket功能之外，实际上也可以处理HTTP长连接。只需要增加[onRequest](/http_server?id=on)事件监听即可实现Comet方案HTTP长轮询。

!> 详细使用方法参考[Swoole\WebSocket](/websocket_server)
