# WebSocket\Server

?> 通过内置的`WebSocket`服务器支持，通过几行`PHP`代码就可以写出一个[异步IO](/learn?id=同步io异步io)的多进程的`WebSocket`服务器。

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9501);

$server->on('open', function (Swoole\WebSocket\Server $server, $request) {
    echo "server: handshake success with fd{$request->fd}\n";
});

$server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
    echo "receive from {$frame->fd}:{$frame->data},opcode:{$frame->opcode},fin:{$frame->finish}\n";
    $server->push($frame->fd, "this is server");
});

$server->on('close', function ($server, $fd) {
    echo "client {$fd} closed\n";
});

$server->start();
```

* **客户端**

  * `Chrome/Firefox/`高版本`IE/Safari`等浏览器内置了`JS`语言的`WebSocket`客户端
  * 微信小程序开发框架内置的`WebSocket`客户端
  * [异步IO](/learn?id=同步io异步io) 的`PHP`程序中可以使用 [Swoole\Coroutine\Http](/coroutine_client/http_client) 作为`WebSocket`客户端
  * `Apache/PHP-FPM`或其他同步阻塞的`PHP`程序中可以使用`swoole/framework`提供的[同步WebSocket客户端](https://github.com/matyhtf/framework/blob/master/libs/Swoole/Client/WebSocket.php)
  * 非`WebSocket`客户端不能与`WebSocket`服务器通信

* **如何判断连接是否为WebSocket客户端**

?> 通过使用 [$server->connection_info($fd)](/server/methods?id=getclientinfo) 获取连接信息，返回的数组中有一项为 [websocket_status](/websocket_server?id=连接状态)，根据此状态可以判断是否为`WebSocket`客户端。

## 事件

?> `WebSocket`服务器除了接收 [Swoole\Server](/server/methods) 和[Swoole\Http\Server](/http_server)基类的回调函数外，额外增加了`3`个回调函数设置。其中：

* `onMessage`回调函数为必选
* `onOpen`和`onHandShake`回调函数为可选

### onHandShake

?> **`WebSocket`建立连接后进行握手。`WebSocket`服务器会自动进行`handshake`握手的过程，如果用户希望自己进行握手处理，可以设置`onHandShake`事件回调函数。**

```php
onHandShake(Swoole\Http\Request $request, Swoole\Http\Response $response);
```

* **提示**

  * `onHandShake`事件回调是可选的
  * 设置`onHandShake`回调函数后不会再触发`onOpen`事件，需要应用代码自行处理，可以使用`$server->defer`调用`onOpen`逻辑
  * `onHandShake`中必须调用 [response->status()](/http_server?id=status) 设置状态码为`101`并调用[response->end()](/http_server?id=end)响应, 否则会握手失败.
  * 内置的握手协议为`Sec-WebSocket-Version: 13`，低版本浏览器需要自行实现握手

* **注意**

!>  如果需要自行处理`handshake`的时候，再设置这个回调函数。如果不需要“自定义”握手过程，那么不要设置该回调，使用`Swoole`默认的握手即可。下面是“自定义”`handshake`事件回调函数中必须要具备的：

```php
$server->on('handshake', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
    // print_r( $request->header );
    // if (如果不满足我某些自定义的需求条件，那么返回end输出，返回false，握手失败) {
    //    $response->end();
    //     return false;
    // }

    // websocket握手连接算法验证
    $secWebSocketKey = $request->header['sec-websocket-key'];
    $patten = '#^[+/0-9A-Za-z]{21}[AQgw]==$#';
    if (0 === preg_match($patten, $secWebSocketKey) || 16 !== strlen(base64_decode($secWebSocketKey))) {
        $response->end();
        return false;
    }
    echo $request->header['sec-websocket-key'];
    $key = base64_encode(
        sha1(
            $request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
            true
        )
    );

    $headers = [
        'Upgrade' => 'websocket',
        'Connection' => 'Upgrade',
        'Sec-WebSocket-Accept' => $key,
        'Sec-WebSocket-Version' => '13',
    ];

    // WebSocket connection to 'ws://127.0.0.1:9502/'
    // failed: Error during WebSocket handshake:
    // Response must not include 'Sec-WebSocket-Protocol' header if not present in request: websocket
    if (isset($request->header['sec-websocket-protocol'])) {
        $headers['Sec-WebSocket-Protocol'] = $request->header['sec-websocket-protocol'];
    }

    foreach ($headers as $key => $val) {
        $response->header($key, $val);
    }

    $response->status(101);
    $response->end();
});
```

!> 设置`onHandShake`回调函数后不会再触发`onOpen`事件，需要应用代码自行处理，可以使用`$server->defer`调用`onOpen`逻辑

```php
$server->on('handshake', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
    // 省略了握手内容
    $response->status(101);
    $response->end();

    global $server;
    $fd = $request->fd;
    $server->defer(function () use ($fd, $server)
    {
      echo "Client connected\n";
      $server->push($fd, "hello, welcome\n");
    });
});
```

### onOpen

?> **当`WebSocket`客户端与服务器建立连接并完成握手后会回调此函数。**

```php
onOpen(Swoole\WebSocket\Server $server, Swoole\Http\Request $request);
```

* **提示**

    * `$request` 是一个[HTTP](/http_server?id=httprequest)请求对象，包含了客户端发来的握手请求信息
    * `onOpen`事件函数中可以调用 [push](/websocket_server?id=push) 向客户端发送数据或者调用 [close](/server/methods?id=close) 关闭连接
    * `onOpen`事件回调是可选的

### onMessage

?> **当服务器收到来自客户端的数据帧时会回调此函数。**

```php
onMessage(Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame)
```

* **提示**

  * `$frame` 是[Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe)对象，包含了客户端发来的数据帧信息
  * `onMessage`回调必须被设置，未设置服务器将无法启动
  * 客户端发送的`ping`帧不会触发`onMessage`，底层会自动回复`pong`包，也可设置[open_websocket_ping_frame
](/websocket_server?id=open_websocket_ping_frame)参数手动处理

* `Swoole\WebSocket\Frame $frame`

属性 | 说明
---|---
$frame->fd | 客户端的`socket id`，使用`$server->push`推送数据时需要用到
$frame->data | 数据内容，可以是文本内容也可以是二进制数据，可以通过`opcode`的值来判断
$frame->opcode | `WebSocket`的`OPCode`类型，可以参考`WebSocket`协议标准文档
$frame->finish | 表示数据帧是否完整，一个`WebSocket`请求可能会分成多个数据帧进行发送（底层已经实现了自动合并数据帧，现在不用担心接收到的数据帧不完整）

!> `$frame->data` 如果是文本类型，编码格式必然是`UTF-8`，这是`WebSocket`协议规定的

* **OPCode与数据类型**

OPCode | 数据类型
---|---
WEBSOCKET_OPCODE_TEXT = 0x1 | 文本数据
WEBSOCKET_OPCODE_BINARY = 0x2 | 二进制数据

### onRequest

?> `WebSocket\Server`继承自[Http\Server](/http_server)，所以`Http\Server`提供的所有`API`和配置项都可以使用。请参考[Http\Server](/http_server)章节。

* 设置了[onRequest](/http_server?id=on)回调，`WebSocket\Server`也可以同时作为`HTTP`服务器
* 未设置[onRequest](/http_server?id=on)回调，`WebSocket\Server`收到`HTTP`请求后会返回`HTTP 400`错误页面
* 如果想通过接收`HTTP`触发所有`WebSocket`的推送，需要注意作用域的问题，面向过程请使用`global`对`WebSocket\Server`进行引用，面向对象可以把`WebSocket\Server`设置成一个成员属性

#### 面向过程代码

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9501);
$server->on('open', function (Swoole\WebSocket\Server $server, $request) {
    echo "server: handshake success with fd{$request->fd}\n";
});
$server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
    echo "receive from {$frame->fd}:{$frame->data},opcode:{$frame->opcode},fin:{$frame->finish}\n";
    $server->push($frame->fd, "this is server");
});
$server->on('close', function ($server, $fd) {
    echo "client {$fd} closed\n";
});
$server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    global $server;//调用外部的server
    // $server->connections 遍历所有websocket连接用户的fd，给所有用户推送
    foreach ($server->connections as $fd) {
        // 需要先判断是否是正确的websocket连接，否则有可能会push失败
        if ($server->isEstablished($fd)) {
            $server->push($fd, $request->get['message']);
        }
    }
});
$server->start();
```

#### 面向对象代码

```php
class WebSocketTest
{
    public $server;

    public function __construct()
    {
        $this->server = new Swoole\WebSocket\Server("0.0.0.0", 9501);
        $this->server->on('open', function (Swoole\WebSocket\Server $server, $request) {
            echo "server: handshake success with fd{$request->fd}\n";
        });
        $this->server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
            echo "receive from {$frame->fd}:{$frame->data},opcode:{$frame->opcode},fin:{$frame->finish}\n";
            $server->push($frame->fd, "this is server");
        });
        $this->server->on('close', function ($ser, $fd) {
            echo "client {$fd} closed\n";
        });
        $this->server->on('request', function ($request, $response) {
            // 接收http请求从get获取message参数的值，给用户推送
            // $this->server->connections 遍历所有websocket连接用户的fd，给所有用户推送
            foreach ($this->server->connections as $fd) {
                // 需要先判断是否是正确的websocket连接，否则有可能会push失败
                if ($this->server->isEstablished($fd)) {
                    $this->server->push($fd, $request->get['message']);
                }
            }
        });
        $this->server->start();
    }
}

new WebSocketTest();
```

### onDisconnect

?> **用于在连接关闭时区分连接是否为 WebSocket 连接。**

!> Swoole 版本 >= `v4.7.0` 可用

```php
onDisconnect(Swoole\WebSocket\Server $server, $fd)
```

!> 设置了 `onDisconnect` 事件回调，非 WebSocket 请求或者在 [onRequest](/websocket_server?id=onrequest) 调用 `$response->close()` 方法，`都会回调onDisconnect`。而在 [onRequest](/websocket_server?id=onrequest) 事件中正常结束则不会调用 `onClose` 或 `onDisconnect` 事件。  

## 方法

`WebSocket\Server`是 [Server](/server/methods) 的子类，因此可以调用`Server`的全部方法。

需要注意`WebSocket`服务器向客户端发送数据应当使用`WebSocket\Server::push`方法，此方法会进行`WebSocket`协议打包。而 [Server::send](/server/methods?id=send) 方法是原始的`TCP`发送接口。

[WebSocket\Server->disconnect()](/websocket_server?id=disconnect)方法可以从服务端主动关闭一个`WebSocket`连接，可以指定状态码(根据`WebSocket`协议，可使用的状态码为十进制的一个整数，取值可以是`1000`或`4000-4999`)和关闭原因(采用`utf-8`编码、字节长度不超过`125`的字符串)。在未指定情况下状态码为`1000`，关闭原因为空。

### push

?> **向`WebSocket`客户端连接推送数据，长度最大不得超过`2M`。**

```php
Swoole\WebSocket\Server->push(int $fd, string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, bool $finish = true): bool

// v4.4.12版本改为了flags参数
Swoole\WebSocket\Server->push(int $fd, string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): bool
```

* **参数** 

  * **`int $fd`**

    * **功能**：客户端连接的`ID` 【如果指定的`$fd`对应的`TCP`连接并非`WebSocket`客户端，将会发送失败】
    * **默认值**：无
    * **其它值**：无

  * **`string $data`**

    * **功能**：要发送的数据内容
    * **默认值**：无
    * **其它值**：无

  !> Swoole版本 >= v4.2.0 传入的`$data`，如果是 [Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe) 对象则其后续参数会被忽略

  * **`int $opcode`**

    * **功能**：指定发送数据内容的格式 【默认为文本。发送二进制内容`$opcode`参数需要设置为`WEBSOCKET_OPCODE_BINARY`】
    * **默认值**：`WEBSOCKET_OPCODE_TEXT`
    * **其它值**：`WEBSOCKET_OPCODE_BINARY`

  * **`bool $finish`**

    * **功能**：是否发送完成
    * **默认值**：`true`
    * **其它值**：`false`

!> 自`v4.4.12`版本起，`finish`参数（`bool`型）改为`flags`参数（`int`型）以支持`WebSocket`压缩，`finish`对应`SWOOLE_WEBSOCKET_FLAG_FIN`值为`1`，原有`bool`型值会隐式转换为`int`型，此改动向下兼容无影响。 此外压缩`flag`为`SWOOLE_WEBSOCKET_FLAG_COMPRESS`。

!> [BASE 模式](/learn?id=base模式的限制：) 不支持跨进程 `push` 发送数据。

### exist

?> **判断`WebSocket`客户端是否存在，并且状态为`Active`状态。**

!> `v4.3.0`以后, 此`API`仅用于判断连接是否存在, 请使用`isEstablished`判断是否为`WebSocket`连接

```php
Swoole\WebSocket\Server->exist(int $fd): bool
```

* **返回值**

  * 连接存在，并且已完成`WebSocket`握手，返回`true`
  * 连接不存在或尚未完成握手，返回`false`

### pack

?> **打包WebSocket消息。**

```php
Swoole\WebSocket\Server::pack(string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, bool $finish = true, bool $mask = false): string

// v4.4.12版本改为了flags参数
Swoole\WebSocket\Server::pack(string $data, int $opcode = WEBSOCKET_OPCODE_TEXT, int $flags = SWOOLE_WEBSOCKET_FLAG_FIN): string
```

* **参数** 

  * **`string $data`**

    * **功能**：消息内容
    * **默认值**：无
    * **其它值**：无

  * **`int $opcode`**

    * **功能**：指定发送数据内容的格式 【默认为文本。发送二进制内容`$opcode`参数需要设置为`WEBSOCKET_OPCODE_BINARY`】
    * **默认值**：`WEBSOCKET_OPCODE_TEXT`
    * **其它值**：`WEBSOCKET_OPCODE_BINARY`

  * **`bool $finish`**

    * **功能**：帧是否完成
    * **默认值**：无
    * **其它值**：无

    !> 自`v4.4.12`版本起，`finish`参数（`bool`型）改为`flags`参数（`int`型）以支持`WebSocket`压缩，`finish`对应`SWOOLE_WEBSOCKET_FLAG_FIN`值为`1`，原有`bool`型值会隐式转换为`int`型，此改动向下兼容无影响。

  * **`bool $mask`**

    * **功能**：是否设置掩码【`v4.4.12`已移除此参数】
    * **默认值**：无
    * **其它值**：无

* **返回值**

  * 返回打包好的`WebSocket`数据包，可通过`Swoole\Server`基类的 [send()](/server/methods?id=send) 发送给对端

* **示例**

```php
$ws = new Swoole\Server('127.0.0.1', 9501 , SWOOLE_BASE);

$ws->set(array(
    'log_file' => '/dev/null'
));

$ws->on('WorkerStart', function (\Swoole\Server $serv) {
});

$ws->on('receive', function ($serv, $fd, $threadId, $data) {
    $sendData = "HTTP/1.1 101 Switching Protocols\r\n";
    $sendData .= "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: IFpdKwYy9wdo4gTldFLHFh3xQE0=\r\n";
    $sendData .= "Sec-WebSocket-Version: 13\r\nServer: swoole-http-server\r\n\r\n";
    $sendData .= Swoole\WebSocket\Server::pack("hello world\n");
    $serv->send($fd, $sendData);
});

$ws->start();
```

### unpack

?> **解析`WebSocket`数据帧。**

```php
Swoole\WebSocket\Server::unpack(string $data): Swoole\WebSocket\Frame|false;
```

* **参数** 

  * **`string $data`**

    * **功能**：消息内容
    * **默认值**：无
    * **其它值**：无

* **返回值**

  * 解析失败返回`false`，解析成功返回[Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe)对象

### disconnect

?> **主动向`WebSocket`客户端发送关闭帧并关闭该连接。**

!> Swoole版本 >= `v4.0.3` 可用

```php
Swoole\WebSocket\Server->disconnect(int $fd, int $code = SWOOLE_WEBSOCKET_CLOSE_NORMAL, string $reason = ''): bool
```

* **参数** 

  * **`int $fd`**

    * **功能**：客户端连接的`ID`【如果指定的`$fd`对应的`TCP`连接并非`WebSocket`客户端，将会发送失败】
    * **默认值**：无
    * **其它值**：无

  * **`int $code`**

    * **功能**：关闭连接的状态码【根据`RFC6455`，对于应用程序关闭连接状态码，取值范围为`1000`或`4000-4999`之间】
    * **默认值**：`SWOOLE_WEBSOCKET_CLOSE_NORMAL`
    * **其它值**：无

  * **`string $reason`**

    * **功能**：关闭连接的原因【`utf-8`格式字符串，字节长度不超过`125`】
    * **默认值**：无
    * **其它值**：无

* **返回值**

  * 发送成功返回`true`，发送失败或状态码非法时返回`false`

### isEstablished

?> **检查连接是否为有效的`WebSocket`客户端连接。**

?> 此函数与`exist`方法不同，`exist`方法仅判断是否为`TCP`连接，无法判断是否为已完成握手的`WebSocket`客户端。

```php
Swoole\WebSocket\Server->isEstablished(int $fd): bool
```

* **参数** 

  * **`int $fd`**

    * **功能**：客户端连接的`ID`【如果指定的`$fd`对应的`TCP`连接并非`WebSocket`客户端，将会发送失败】
    * **默认值**：无
    * **其它值**：无

## 常量

### 数据帧类型

常量 | 对应值 | 说明
---|---|---
WEBSOCKET_OPCODE_TEXT | 0x1 | UTF-8文本字符数据
WEBSOCKET_OPCODE_BINARY | 0x2 | 二进制数据
WEBSOCKET_OPCODE_CLOSE | 0x8 | 关闭帧类型数据
WEBSOCKET_OPCODE_PING | 0x9 | ping类型数据
WEBSOCKET_OPCODE_PONG | 0x10 | pong类型数据

### 连接状态

常量 | 对应值 | 说明
---|---|---
WEBSOCKET_STATUS_CONNECTION | 1 | 连接进入等待握手
WEBSOCKET_STATUS_HANDSHAKE | 2 | 正在握手
WEBSOCKET_STATUS_ACTIVE | 3 | 已握手成功等待浏览器发送数据帧
WEBSOCKET_STATUS_CLOSING | 4 | 连接正在进行关闭握手，即将关闭

## 选项

?> `WebSocket\Server`是`Server`的子类，可以使用[Server->set()](/server/methods?id=set)方法传入配置选项，设置某些参数。

### websocket_subprotocol

?> **设置`WebSocket`子协议。**

?> 设置后握手响应的`HTTP`头会增加`Sec-WebSocket-Protocol: {$websocket_subprotocol}`。具体使用方法请参考`WebSocket`协议相关`RFC`文档。

```php
$server->set([
    'websocket_subprotocol' => 'chat',
]);
```

### open_websocket_close_frame

?> **启用`WebSocket`协议中关闭帧（`opcode`为`0x08`的帧）在`onMessage`回调中接收，默认为`false`。**

?> 开启后，可在`Swoole\WebSocket\Server`中的`onMessage`回调中接收到客户端或服务端发送的关闭帧，开发者可自行对其进行处理。

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9501);
$server->set(array("open_websocket_close_frame" => true));
$server->on('open', function (Swoole\WebSocket\Server $server, $request) {
});

$server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
    if ($frame->opcode == 0x08) {
        echo "Close frame received: Code {$frame->code} Reason {$frame->reason}\n";
    } else {
        echo "Message received: {$frame->data}\n";
    }
});

$server->on('close', function ($server, $fd) {
});

$server->start();
```

### open_websocket_ping_frame

?> **启用`WebSocket`协议中`Ping`帧（`opcode`为`0x09`的帧）在`onMessage`回调中接收，默认为`false`。**

?> 开启后，可在`Swoole\WebSocket\Server`中的`onMessage`回调中接收到客户端或服务端发送的`Ping`帧，开发者可自行对其进行处理。

!> Swoole版本 >= `v4.5.4` 可用

```php
$server->set([
    'open_websocket_ping_frame' => true,
]);
```

!> 值为`false`时底层会自动回复`Pong`帧，但如果设为`true`后则需要开发者自行回复`Pong`帧。

* **示例**

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9501);
$server->set(array("open_websocket_ping_frame" => true));
$server->on('open', function (Swoole\WebSocket\Server $server, $request) {
});

$server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
    if ($frame->opcode == 0x09) {
        echo "Ping frame received: Code {$frame->opcode}\n";
        // 回复 Pong 帧
        $pongFrame = new Swoole\WebSocket\Frame;
        $pongFrame->opcode = WEBSOCKET_OPCODE_PONG;
        $server->push($frame->fd, $pongFrame);
    } else {
        echo "Message received: {$frame->data}\n";
    }
});

$server->on('close', function ($server, $fd) {
});

$server->start();
```

### open_websocket_pong_frame

?> **启用`WebSocket`协议中`Pong`帧（`opcode`为`0x0A`的帧）在`onMessage`回调中接收，默认为`false`。**

?> 开启后，可在`Swoole\WebSocket\Server`中的`onMessage`回调中接收到客户端或服务端发送的`Pong`帧，开发者可自行对其进行处理。

!> Swoole版本 >= `v4.5.4` 可用

```php
$server->set([
    'open_websocket_pong_frame' => true,
]);
```

* **示例**

```php
$server = new Swoole\WebSocket\Server("0.0.0.0", 9501);
$server->set(array("open_websocket_pong_frame" => true));
$server->on('open', function (Swoole\WebSocket\Server $server, $request) {
});

$server->on('message', function (Swoole\WebSocket\Server $server, $frame) {
    if ($frame->opcode == 0xa) {
        echo "Pong frame received: Code {$frame->opcode}\n";
    } else {
        echo "Message received: {$frame->data}\n";
    }
});

$server->on('close', function ($server, $fd) {
});

$server->start();
```

### websocket_compression

?> **启用数据压缩**

?> 为`true`时允许对帧进行`zlib`压缩，具体是否能够压缩取决于客户端是否能够处理压缩（根据握手信息决定，参见`RFC-7692`） 需要配合`flags`参数`SWOOLE_WEBSOCKET_FLAG_COMPRESS`来真正地对具体的某个帧进行压缩，具体使用方法[见此节](/websocket_server?id=websocket帧压缩-（rfc-7692）)

!> Swoole版本 >= `v4.4.12` 可用

## 其他

!> 相关示例代码可以在 [WebSocket 单元测试](https://github.com/swoole/swoole-src/tree/master/tests/swoole_websocket_server) 中找到

### Swoole\WebSocket\Frame

?> 在`v4.2.0`版本中, 新增了服务端和客户端发送[Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe)对象的支持  
在`v4.4.12`版本中，新增了`flags`属性以支持`WebSocket`压缩帧，同时增加了一个新的子类`Swoole\WebSocket\CloseFrame`

一个普通的`frame`对象具有以下属性

```php
object(Swoole\WebSocket\Frame)#1 (4) {
  ["fd"]      =>  int(0)
  ["data"]    =>  NULL
  ["opcode"]  =>  int(1)
  ["finish"]  =>  bool(true)
}
```

### Swoole\WebSocket\CloseFrame

一个普通的`close frame`对象具有以下属性, 多了`code`和`reason`属性, 记录了关闭的错误代码和原因，code可在[websocket协议中定义的错误码](https://developer.mozilla.org/zh-CN/docs/Web/API/CloseEvent) 查询，reason若是对端没有明确给出，则为空

如果服务端需要接收`close frame`, 需要通过`$server->set`开启[open_websocket_close_frame](/websocket_server?id=open_websocket_close_frame)参数

```php
object(Swoole\WebSocket\CloseFrame)#1 (6) {
  ["fd"]      =>  int(0)
  ["data"]    =>  NULL
  ["finish"]  =>  bool(true)
  ["opcode"]  =>  int(8)
  ["code"]    =>  int(1000)
  ["reason"]  =>  string(0) ""
}
```

在用于发送时, `fd`属性会被忽略(因为服务器端`fd`是第一个参数, 客户端无需指定`fd`)，所以`fd`是一个只读属性

### WebSocket帧压缩 （RFC-7692）

?> 首先你需要配置`'websocket_compression' => true`来启用压缩（`WebSocket`握手时将与对端交换压缩支持信息）后，你可以使用 `flag SWOOLE_WEBSOCKET_FLAG_COMPRESS` 来对具体的某个帧进行压缩

#### 示例

* **服务端**

```php
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$server = new Server('127.0.0.1', 9501);
$server->set(['websocket_compression' => true]);
$server->on('message', function (Server $server, Frame $frame) {
    $server->push(
        $frame->fd,
        'Hello Swoole',
        SWOOLE_WEBSOCKET_OPCODE_TEXT,
        SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS
    );
    // $server->push($frame->fd, $frame); // 或者 服务端可以直接原封不动转发客户端的帧对象
});
$server->start();
```

* **客户端**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $cli = new Client('127.0.0.1', 9501);
    $cli->set(['websocket_compression' => true]);
    $cli->upgrade('/');
    $cli->push(
        'Hello Swoole',
        SWOOLE_WEBSOCKET_OPCODE_TEXT,
        SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS
    );
});
```

### 发送Ping帧

?> 由于 WebSocket 是长连接，如果一定时间内没有通讯，连接可能会断开。这时候需要心跳机制，WebSocket 协议包含了 Ping 和 Pong 两个帧，可以定时发送 Ping 帧来保持长连接。

#### 示例

* **服务端**

```php
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$server = new Server('127.0.0.1', 9501);
$server->on('message', function (Server $server, Frame $frame) {
    $pingFrame = new Frame;
    $pingFrame->opcode = WEBSOCKET_OPCODE_PING;
    $server->push($frame->fd, $pingFrame);
});
$server->start();
```

* **客户端**

```php
use Swoole\WebSocket\Frame;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $cli = new Client('127.0.0.1', 9501);
    $cli->upgrade('/');
    $pingFrame = new Frame;
    $pingFrame->opcode = WEBSOCKET_OPCODE_PING;
    // 发送 PING
    $cli->push($pingFrame);
    
    // 接收 PONG
    $pongFrame = $cli->recv();
    var_dump($pongFrame->opcode === WEBSOCKET_OPCODE_PONG);
});
```
