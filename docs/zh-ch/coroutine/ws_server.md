# WebSocket服务器

?> 完全协程化的WebSocket服务器实现，继承自[Coroutine\Http\Server](/coroutine/http_server)，底层提供了对`WebSocket`协议的支持，在此不再赘述，只说差异。

!> 此章节在v4.4.13后可用。

## 完整示例

```php
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\CloseFrame;
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

run(function () {
    $server = new Server('127.0.0.1', 9502, false);
    $server->handle('/websocket', function (Request $request, Response $ws) {
        $ws->upgrade();
        while (true) {
            $frame = $ws->recv();
            if ($frame === '') {
                $ws->close();
                break;
            } else if ($frame === false) {
                echo 'errorCode: ' . swoole_last_error() . "\n";
                $ws->close();
                break;
            } else {
                if ($frame->data == 'close' || get_class($frame) === CloseFrame::class) {
                    $ws->close();
                    break;
                }
                $ws->push("Hello {$frame->data}!");
                $ws->push("How are you, {$frame->data}?");
            }
        }
    });

    $server->handle('/', function (Request $request, Response $response) {
        $response->end(<<<HTML
    <h1>Swoole WebSocket Server</h1>
    <script>
var wsServer = 'ws://127.0.0.1:9502/websocket';
var websocket = new WebSocket(wsServer);
websocket.onopen = function (evt) {
    console.log("Connected to WebSocket server.");
    websocket.send('hello');
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
</script>
HTML
        );
    });

    $server->start();
});
```

### 群发示例

```php
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\WebSocket\CloseFrame;
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

run(function () {
    $server = new Server('127.0.0.1', 9502, false);
    $server->handle('/websocket', function (Request $request, Response $ws) {
        $ws->upgrade();
        global $wsObjects;
        $objectId = spl_object_id($ws);
        $wsObjects[$objectId] = $ws;
        while (true) {
            $frame = $ws->recv();
            if ($frame === '') {
                unset($wsObjects[$objectId]);
                $ws->close();
                break;
            } else if ($frame === false) {
                echo 'errorCode: ' . swoole_last_error() . "\n";
                $ws->close();
                break;
            } else {
                if ($frame->data == 'close' || get_class($frame) === CloseFrame::class) {
                    unset($wsObjects[$objectId]);
                    $ws->close();
                    break;
                }
                foreach ($wsObjects as $obj) {
                    $obj->push("Server：{$frame->data}");
                }
            }
        }
    });
    $server->start();
});
```

## 处理流程

* `$ws->upgrade()`：向客户端发送`WebSocket`握手消息
* `while(true)`循环处理消息的接收和发送
* `$ws->recv()`接收`WebSocket`消息帧
* `$ws->push()`向对端发送数据帧
* `$ws->close()`关闭连接

!> `$ws`是一个`Swoole\Http\Response`对象，具体每个方法使用方法参考下文。

## 方法

### upgrade()

发送`WebSocket`握手成功信息。

!> 此方法不要用于[异步风格](/http_server)的服务器中

```php
Swoole\Http\Response->upgrade(): bool
```

### recv()

接收`WebSocket`消息。

!> 此方法不要用于[异步风格](/http_server)的服务器中，调用`recv`方法时会[挂起](/coroutine?id=协程调度)当前协程，等待数据到来时再恢复协程的执行

```php
Swoole\Http\Response->recv(float $timeout = 0): Swoole\WebSocket\Frame | false | string
```

* **返回值**

  * 成功收到消息，返回`Swoole\WebSocket\Frame`对象，请参考 [Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe)
  * 失败返回`false`，请使用 [swoole_last_error()](/functions?id=swoole_last_error) 获取错误码
  * 连接关闭返回空字符串
  * 返回值处理可参考 [群发示例](/coroutine/ws_server?id=群发示例)

### push()

发送`WebSocket`数据帧。

!> 此方法不要用于[异步风格](/http_server)的服务器中，发送大数据包时，需要监听可写，因此会引起多次[协程切换](/coroutine?id=协程调度)

```php
Swoole\Http\Response->push(string|object $data, int $opcode = WEBSOCKET_OPCODE_TEXT, bool $finish = true): bool
```

* **参数** 

  !> 若传入的`$data`是 [Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe) 对象则其后续参数会被忽略，支持发送各种帧类型

  * **`string|object $data`**

    * **功能**：要发送的内容
    * **默认值**：无
    * **其它值**：无

  * **`int $opcode`**

    * **功能**：指定发送数据内容的格式 【默认为文本。发送二进制内容`$opcode`参数需要设置为`WEBSOCKET_OPCODE_BINARY`】
    * **默认值**：`WEBSOCKET_OPCODE_TEXT`
    * **其它值**：`WEBSOCKET_OPCODE_BINARY`

  * **`bool $finish`**

    * **功能**：是否发送完成
    * **默认值**：`true`
    * **其它值**：`false`

### close()

关闭`WebSocket`连接。

!> 此方法不要用于[异步风格](/http_server)的服务器中，在v4.4.15以前版本会误报`Warning`忽略即可。

```php
Swoole\Http\Response->close(): bool
```
