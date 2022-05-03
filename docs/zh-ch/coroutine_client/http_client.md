# 协程HTTP/WebSocket客户端

协程版`HTTP`客户端的底层用纯`C`编写，不依赖任何第三方扩展库，拥有超高的性能。

* 支持`Http-Chunk`、`Keep-Alive`特性，支持`form-data`格式
* `HTTP`协议版本为`HTTP/1.1`
* 支持升级为`WebSocket`客户端
* `gzip`压缩格式支持需要依赖`zlib`库
* 客户端仅实现核心的功能，实际项目建议使用 [Saber](https://github.com/swlib/saber)

## 属性

### errCode

错误状态码。当`connect/send/recv/close`失败或者超时时，会自动设置`Swoole\Coroutine\Http\Client->errCode`的值

```php
Swoole\Coroutine\Http\Client->errCode: int
```

`errCode`的值等于`Linux errno`。可使用`socket_strerror`将错误码转为错误信息。

```php
// 如果connect refuse，错误码为111
// 如果超时，错误码为110
echo socket_strerror($client->errCode);
```

!> 参考：[Linux 错误码列表](/other/errno?id=linux)

### body

存储上次请求的返回包体。

```php
Swoole\Coroutine\Http\Client->body: string
```

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $cli = new Client('httpbin.org', 80);
    $cli->get('/get');
    echo $cli->body;
    $cli->close();
});
```

### statusCode

HTTP状态码，如200、404等。状态码如果为负数，表示连接存在问题。[查看更多](/coroutine_client/http_client?id=getstatuscode)

```php
Swoole\Coroutine\Http\Client->statusCode: int
```

## 方法

### __construct()

构造方法。

```php
Swoole\Coroutine\Http\Client::__construct(string $host, int $port, bool $ssl = false);
```

  * **参数** 

    * **`string $host`**
      * **功能**：目标服务器主机地址【可以为IP或域名，底层自动进行域名解析，若是本地UNIXSocket则应以形如`unix://tmp/your_file.sock`的格式填写；若是域名不需要填写协议头`http://`或`https://`】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：目标服务器主机端口
      * **默认值**：无
      * **其它值**：无

    * **`bool $ssl`**
      * **功能**：是否启用`SSL/TLS`隧道加密，如果目标服务器是https必须设置`$ssl`参数为`true`
      * **默认值**：`false`
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 80);
    $client->setHeaders([
        'Host' => 'localhost',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $client->set(['timeout' => 1]);
    $client->get('/index.php');
    echo $client->body;
    $client->close();
});
```

### set()

设置客户端参数。

```php
Swoole\Coroutine\Http\Client->set(array $options);
```

此方法与`Swoole\Client->set`接收的参数完全一致，可参考 [Swoole\Client->set](/client?id=set) 方法的文档。

`Swoole\Coroutine\Http\Client` 额外增加了一些选项，来控制`HTTP`和`WebSocket`客户端。

#### 额外选项

##### 超时控制

设置`timeout`选项，启用HTTP请求超时检测。单位为秒，最小粒度支持毫秒。

```php
$http->set(['timeout' => 3.0]);
```

* 连接超时或被服务器关闭连接，`statusCode`将设置为`-1`
* 在约定的时间内服务器未返回响应，请求超时，`statusCode`将设置为`-2`
* 请求超时后底层会自动切断连接
* 参考[客户端超时规则](/coroutine_client/init?id=超时规则)

##### keep_alive

设置`keep_alive`选项，启用或关闭HTTP长连接。

```php
$http->set(['keep_alive' => false]);
```

##### websocket_mask

> 由于RFC规定, v4.4.0后此配置默认开启, 但会导致性能损耗, 如服务器端无强制要求可以设置false关闭

`WebSocket`客户端启用或关闭掩码。默认为启用。启用后会对WebSocket客户端发送的数据使用掩码进行数据转换。

```php
$http->set(['websocket_mask' => false]);
```

##### websocket_compression

> 需要`v4.4.12`或更高版本

为`true`时**允许**对帧进行zlib压缩，具体是否能够压缩取决于服务端是否能够处理压缩（根据握手信息决定，参见`RFC-7692`）

需要配合flags参数`SWOOLE_WEBSOCKET_FLAG_COMPRESS`来真正地对具体的某个帧进行压缩，具体使用方法[见此节](/websocket_server?id=websocket帧压缩-（rfc-7692）)

```php
$http->set(['websocket_compression' => true]);
```

### setMethod()

设置请求方法。仅在当前请求有效，发送请求后会立刻清除method设置。

```php
Swoole\Coroutine\Http\Client->setMethod(string $method): void
```

  * **参数** 

    * **`string $method`**
      * **功能**：设置方法 
      * **默认值**：无
      * **其它值**：无

      !> 必须为符合`HTTP`标准的方法名称，如果`$method`设置错误可能会被`HTTP`服务器拒绝请求

  * **示例**

```php
$http->setMethod("PUT");
```

### setHeaders()

设置HTTP请求头。

```php
Swoole\Coroutine\Http\Client->setHeaders(array $headers): void
```

  * **参数** 

    * **`array $headers`**
      * **功能**：设置请求头 【必须为键值对应的数组，底层会自动映射为`$key`: `$value`格式的`HTTP`标准头格式】
      * **默认值**：无
      * **其它值**：无

!> `setHeaders`设置的`HTTP`头在`Coroutine\Http\Client`对象存活期间的每次请求永久有效；重新调用`setHeaders`会覆盖上一次的设置

### setCookies()

设置`Cookie`, 值将会被进行`urlencode`编码, 若想保持原始信息, 请自行用`setHeaders`设置名为`Cookie`的`header`。

```php
Swoole\Coroutine\Http\Client->setCookies(array $cookies): void
```

  * **参数** 

    * **`array $cookies`**
      * **功能**：设置 `COOKIE` 【必须为键值对应数组】
      * **默认值**：无
      * **其它值**：无

!> -设置`COOKIE`后在客户端对象存活期间会持续保存  
-服务器端主动设置的`COOKIE`会合并到`cookies`数组中，可读取`$client->cookies`属性获得当前`HTTP`客户端的`COOKIE`信息  
-重复调用`setCookies`方法，会覆盖当前的`Cookies`状态，这会丢弃之前服务器端下发的`COOKIE`以及之前主动设置的`COOKIE`

### setData()

设置HTTP请求的包体。

```php
Swoole\Coroutine\Http\Client->setData(string|array $data): void
```

  * **参数** 

    * **`string|array $data`**
      * **功能**：设置请求的包体
      * **默认值**：无
      * **其它值**：无

  * **提示**

    * 设置`$data`后并且未设置`$method`，底层会自动设置为POST
    * 如果`$data`为数组时且`Content-Type`为`urlencoded`格式, 底层将会自动进行`http_build_query`
    * 如果使用了`addFile`或`addData`导致启用了`form-data`格式, `$data`值为字符串时将会被忽略(因为格式不同), 但为数组时底层将会以`form-data`格式追加数组中的字段

### addFile()

添加POST文件。

!> 使用`addFile`会自动将`POST`的`Content-Type`将变更为`form-data`。`addFile`底层基于`sendfile`，可支持异步发送超大文件。

```php
Swoole\Coroutine\Http\Client->addFile(string $path, string $name, string $mimeType = null, string $filename = null, int $offset = 0, int $length = 0): void
```

  * **参数** 

    * **`string $path`**
      * **功能**：文件的路径【必选参数，不能为空文件或者不存在的文件】
      * **默认值**：无
      * **其它值**：无

    * **`string $name`**
      * **功能**：表单的名称【必选参数，`FILES`参数中的`key`】
      * **默认值**：无
      * **其它值**：无

    * **`string $mimeType`**
      * **功能**：文件的`MIME`格式，【可选参数，底层会根据文件的扩展名自动推断】
      * **默认值**：无
      * **其它值**：无

    * **`string $filename`**
      * **功能**：文件名称【可选参数】
      * **默认值**：`basename($path)`
      * **其它值**：无

    * **`int $offset`**
      * **功能**：上传文件的偏移量【可选参数，可以指定从文件的中间部分开始传输数据。此特性可用于支持断点续传。】
      * **默认值**：无
      * **其它值**：无

    * **`int $length`**
      * **功能**：发送数据的尺寸【可选参数】
      * **默认值**：默认为整个文件的尺寸
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $cli = new Client('httpbin.org', 80);
    $cli->setHeaders([
        'Host' => 'httpbin.org'
    ]);
    $cli->set(['timeout' => -1]);
    $cli->addFile(__FILE__, 'file1', 'text/plain');
    $cli->post('/post', ['foo' => 'bar']);
    echo $cli->body;
    $cli->close();
});
```

### addData()

使用字符串构建上传文件内容。 

!> `addData`在 `v4.1.0` 以上版本可用

```php
Swoole\Coroutine\Http\Client->addData(string $data, string $name, string $mimeType = null, string $filename = null): void
```

  * **参数** 

    * **`string $data`**
      * **功能**：数据内容【必选参数，最大长度不得超过[buffer_output_size](/server/setting?id=buffer_output_size)】
      * **默认值**：无
      * **其它值**：无

    * **`string $name`**
      * **功能**：表单的名称【必选参数，`$_FILES`参数中的`key`】
      * **默认值**：无
      * **其它值**：无

    * **`string $mimeType`**
      * **功能**：文件的`MIME`格式【可选参数，默认为`application/octet-stream`】
      * **默认值**：无
      * **其它值**：无

    * **`string $filename`**
      * **功能**：文件名称【可选参数，默认为`$name`】
      * **默认值**：无
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('httpbin.org', 80);
    $client->setHeaders([
        'Host' => 'httpbin.org'
    ]);
    $client->set(['timeout' => -1]);
    $client->addData(Co::readFile(__FILE__), 'file1', 'text/plain');
    $client->post('/post', ['foo' => 'bar']);
    echo $client->body;
    $client->close();
});
```

### get()

发起 GET 请求。

```php
Swoole\Coroutine\Http\Client->get(string $path): void
```

  * **参数** 

    * **`string $path`**
      * **功能**：设置`URL`路径【如`/index.html`，注意这里不能传入`http://domain`】
      * **默认值**：无
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 80);
    $client->setHeaders([
        'Host' => 'localhost',
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-Encoding' => 'gzip',
    ]);
    $client->get('/index.php');
    echo $client->body;
    $client->close();
});
```

!> 使用`get`会忽略`setMethod`设置的请求方法，强制使用`GET`

### post()

发起 POST 请求。

```php
Swoole\Coroutine\Http\Client->post(string $path, mixed $data): void
```

  * **参数** 

    * **`string $path`**
      * **功能**：设置`URL`路径【如`/index.html`，注意这里不能传入`http://domain`】
      * **默认值**：无
      * **其它值**：无

    * **`mixed $data`**
      * **功能**：请求的包体数据
      * **默认值**：无
      * **其它值**：无

      !> 如果`$data`为数组底层自动会打包为`x-www-form-urlencoded`格式的`POST`内容，并设置`Content-Type`为`application/x-www-form-urlencoded`

  * **注意**

    !> 使用`post`会忽略`setMethod`设置的请求方法，强制使用`POST`

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 80);
    $client->post('/post.php', array('a' => '123', 'b' => '456'));
    echo $client->body;
    $client->close();
});
```

### upgrade()

升级为`WebSocket`连接。

```php
Swoole\Coroutine\Http\Client->upgrade(string $path): bool
```

  * **参数** 

    * **`string $path`**
      * **功能**：设置`URL`路径【如`/`，注意这里不能传入`http://domain`】
      * **默认值**：无
      * **其它值**：无

  * **提示**

    * 某些情况下请求虽然是成功的，`upgrade`返回了`true`，但服务器并未设置`HTTP`状态码为`101`，而是`200`或`403`，这说明服务器拒绝了握手请求
    * `WebSocket`握手成功后可以使用`push`方法向服务器端推送消息，也可以调用`recv`接收消息
    * `upgrade`会产生一次[协程调度](/coroutine?id=协程调度)

  * **示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9501);
    $ret = $client->upgrade('/');
    if ($ret) {
        while(true) {
            $client->push('hello');
            var_dump($client->recv());
            Coroutine::sleep(0.1);
        }
    }
});
```

### push()

向`WebSocket`服务器推送消息。

!> `push`方法必须在`upgrade`成功之后才能执行  
`push`方法不会产生[协程调度](/coroutine?id=协程调度)，写入发送缓存区后会立即返回

```php
Swoole\Coroutine\Http\Client->push(mixed $data, int $opcode = WEBSOCKET_OPCODE_TEXT, bool $finish = true): bool
```

  * **参数** 

    * **`mixed $data`**
      * **功能**：要发送的数据内容【默认为`UTF-8`文本格式，如果为其他格式编码或二进制数据，请使用`WEBSOCKET_OPCODE_BINARY`】
      * **默认值**：无
      * **其它值**：无

      !> Swoole版本 >= v4.2.0 `$data` 可以使用 [Swoole\WebSocket\Frame](/websocket_server?id=swoolewebsocketframe)对象, 支持发送各种帧类型

    * **`int $opcode`**
      * **功能**：操作类型
      * **默认值**：`WEBSOCKET_OPCODE_TEXT`
      * **其它值**：无

      !> `$opcode`必须为合法的`WebSocket OPCode`，否则会返回失败，并打印错误信息`opcode max 10`

    * **`int|bool $finish`**
      * **功能**：操作类型
      * **默认值**：`SWOOLE_WEBSOCKET_FLAG_FIN`
      * **其它值**：无

      !> 自`v4.4.12`版本起，`finish`参数（`bool`型）改为`flags`（`int`型）以支持`WebSocket`压缩，`finish`对应`SWOOLE_WEBSOCKET_FLAG_FIN`值为`1`，原有`bool`型值会隐式转换为`int`型，此改动向下兼容无影响。 此外压缩`flag`为`SWOOLE_WEBSOCKET_FLAG_COMPRESS`。

  * **返回值**

    * 发送成功，返回`true`
    * 连接不存在、已关闭、未完成`WebSocket`，发送失败返回`false`

  * **错误码**

错误码 | 说明
---|---
8502 | 错误的OPCode
8503 | 未连接到服务器或连接已被关闭
8504 | 握手失败

### recv()

接收消息。只为`WebSocket`使用，需要配合`upgrade()`使用，见示例

```php
Swoole\Coroutine\Http\Client->recv(float $timeout = 0)
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：调用`upgrade()`升级为`WebSocket`连接时此参数才有效
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

      !> 设置超时，优先使用指定的参数，其次使用`set`方法中传入的`timeout`配置
  
  * **返回值**

    * 执行成功返回frame对象
    * 失败返回`false`，并检查`Swoole\Coroutine\Http\Client`的`errCode`属性，协程客户端没有`onClose`回调，连接被关闭recv时返回false并且errCode=0
 
  * **示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9501);
    $ret = $client->upgrade('/');
    if ($ret) {
        while(true) {
            $client->push('hello');
            var_dump($client->recv());
            Coroutine::sleep(0.1);
        }
    }
});
```

### download()

通过HTTP下载文件。

!> download与get方法的不同是download收到数据后会写入到磁盘，而不是在内存中对HTTP Body进行拼接。因此download仅使用小量内存，就可以完成超大文件的下载。

```php
Swoole\Coroutine\Http\Client->download(string $path, string $filename,  int $offset = 0): bool
```

  * **参数** 

    * **`string $path`**
      * **功能**：设置`URL`路径
      * **默认值**：无
      * **其它值**：无

    * **`string $filename`**
      * **功能**：指定下载内容写入的文件路径【会自动写入到`downloadFile`属性】
      * **默认值**：无
      * **其它值**：无

    * **`int $offset`**
      * **功能**：指定写入文件的偏移量【此选项可用于支持断点续传，可配合`HTTP`头`Range:bytes=$offset`实现】
      * **默认值**：无
      * **其它值**：无

      !> `$offset`为`0`时若文件已存在，底层会自动清空此文件

  * **返回值**

    * 执行成功返回`true`
    * 打开文件失败或底层`fseek()`文件失败返回`false`

  * **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $host = 'cdn.jsdelivr.net';
    $client = new Client($host, 443, true);
    $client->set(['timeout' => -1]);
    $client->setHeaders([
        'Host' => $host,
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => '*',
        'Accept-Encoding' => 'gzip'
    ]);
    $client->download('/gh/swoole/swoole-src/mascot.png', __DIR__ . '/logo.png');
});
```

### getCookies()

获取`HTTP`响应的`cookie`内容。

```php
Swoole\Coroutine\Http\Client->getCookies(): array|false
```

!> Cookie信息将经过urldecode解码, 想要获取原始Cookie信息请按照下文自行解析

#### 获取重名`Cookie`或`Cookie`原始头信息

```php
var_dump($client->set_cookie_headers);
```

### getHeaders()

返回`HTTP`响应的头信息。

```php
Swoole\Coroutine\Http\Client->getHeaders(): array|false
```

### getStatusCode()

获取`HTTP`响应的状态码。

```php
Swoole\Coroutine\Http\Client->getStatusCode(): int|false
```

  * **提示**

    * **状态码如果为负数，表示连接存在问题。**

状态码 | v4.2.10 以上版本对应常量 | 说明
---|---|---
-1 | SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED | 连接超时，服务器未监听端口或网络丢失，可以读取$errCode获取具体的网络错误码
-2 | SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT | 请求超时，服务器未在规定的timeout时间内返回response
-3 | SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET | 客户端请求发出后，服务器强制切断连接
-4 | SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED | 客户端发送失败(此常量Swoole版本>=`v4.5.9`可用，小于此版本请使用状态码)

### getBody()

获取`HTTP`响应的包体内容。

```php
Swoole\Coroutine\Http\Client->getBody(): string|false
```

### close()

关闭连接。

```php
Swoole\Coroutine\Http\Client->close(): bool
```

!> `close`后如果再次请求 `get`、`post` 等方法时，Swoole会帮你重新连接服务器。

### execute()

更底层的`HTTP`请求方法，需要代码中调用[setMethod](/coroutine_client/http_client?id=setmethod)和[setData](/coroutine_client/http_client?id=setdata)等接口设置请求的方法和数据。

```php
Swoole\Coroutine\Http\Client->execute(string $path): bool
```

* **示例**

```php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $httpClient = new Client('httpbin.org', 80);
    $httpClient->setMethod('POST');
    $httpClient->setData('swoole');
    $status = $httpClient->execute('/post');
    var_dump($status);
    var_dump($httpClient->getBody());
});
```

## 函数

为了方便 `Coroutine\Http\Client` 的使用，增加了三个函数：

!> Swoole版本 >= `v4.6.4` 可用

### request()

发起一个指定请求方式的请求。

```php
function request(string $url, string $method, $data = null, array $options = null, array $headers = null, array $cookies = null)
```

### post()

用于发起一个 `POST` 请求。

```php
function post(string $url, $data, array $options = null, array $headers = null, array $cookies = null)
```

### get()

用于发起一个 `GET` 请求。

```php
function get(string $url, array $options = null, array $headers = null, array $cookies = null)
```

### 使用示例

```php
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\Http\get;
use function Swoole\Coroutine\Http\post;
use function Swoole\Coroutine\Http\request;

run(function () {
    go(function () {
        $data = get('http://httpbin.org/get?hello=world');
        $body = json_decode($data->getBody());
        assert($body->headers->Host === 'httpbin.org');
        assert($body->args->hello === 'world');
    });
    go(function () {
        $random_data = base64_encode(random_bytes(128));
        $data = post('http://httpbin.org/post?hello=world', ['random_data' => $random_data]);
        $body = json_decode($data->getBody());
        assert($body->headers->Host === 'httpbin.org');
        assert($body->args->hello === 'world');
        assert($body->form->random_data === $random_data);
    });
});
```