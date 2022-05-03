# Coroutine\Http2\Client

协程Http2客户端

## 使用示例

```php
use Swoole\Http2\Request;
use Swoole\Coroutine\Http2\Client;
use function Swoole\Coroutine\run;

run(function () {
    $domain = 'www.zhihu.com';
    $cli = new Client($domain, 443, true);
    $cli->set([
        'timeout' => -1,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();
    $req = new Request();
    $req->method = 'POST';
    $req->path = '/api/v4/answers/300000000/voters';
    $req->headers = [
        'host' => $domain,
        'user-agent' => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip'
    ];
    $req->data = '{"type":"up"}';
    $cli->send($req);
    $response = $cli->recv();
    var_dump(assert(json_decode($response->data)->error->code === 10002));
});
```

## 方法

### __construct()

构造方法。

```php
Swoole\Coroutine\Http2\Client::__construct(string $host, int $port, bool $open_ssl = false): void
```

  * **参数** 

    * **`string $host`**
      * **功能**：目标主机的IP地址【`$host`如果为域名底层需要进行一次`DNS`查询】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：目标端口【`Http`一般为`80`端口，`Https`一般为`443`端口】
      * **默认值**：无
      * **其它值**：无

    * **`bool $open_ssl`**
      * **功能**：是否开启`TLS/SSL`隧道加密 【`https`网站必须设置为`true`】
      * **默认值**：`false`
      * **其它值**：`true`

  * **注意**

    !> -如果你需要请求外网URL请修改`timeout`为更大的数值，参考[客户端超时规则](/coroutine_client/init?id=超时规则)  
    -`$ssl`需要依赖`openssl`，必须在编译`Swoole`时启用[--enable-openssl](/environment?id=编译选项)

### set()

设置客户端参数，其它详细配置项请参考 [Swoole\Client::set](/client?id=配置) 配置选项

```php
Swoole\Coroutine\Http2\Client->set(array $options): void
```

### connect()

连接到目标服务器。此方法没有任何参数。

!> 发起`connect`后，底层会自动进行[协程调度](/coroutine?id=协程调度)，当连接成功或失败时`connect`会返回。连接建立后可以调用`send`方法向服务器发送请求。

```php
Swoole\Coroutine\Http2\Client->connect(): bool
```

  * **返回值**

    * 连接成功，返回`true`
    * 连接失败，返回`false`，请检查`errCode`属性获取错误码

### stats()

获取流状态。

```php
Swoole\Coroutine\Http2\Client->stats([$key]): array|bool
```

  * **示例**

```php
var_dump($client->stats(), $client->stats()['local_settings'], $client->stats('local_settings'));
```

### isStreamExist()

判断指定的流是否存在。

```php
Swoole\Coroutine\Http2\Client->isStreamExist(int $stream_id): bool
```

### send()

向服务器发送请求，底层会自动建立一个`Http2`的`stream`。可以同时发起多个请求。

```php
Swoole\Coroutine\Http2\Client->send(Swoole\Http2\Request $request): int|false
```

  * **参数** 

    * **`Swoole\Http2\Request $request`**
      * **功能**：发送 Swoole\Http2\Request 对象
      * **默认值**：无
      * **其它值**：无

  * **返回值**

    * 成功返回流的编号，编号为从`1`开始自增的奇数
    * 失败返回`false`

  * **提示**

    * **Request对象**

      !> `Swoole\Http2\Request` 对象没有任何方法，通过设置对象属性来写入请求相关的信息。

      * `headers` 数组，`HTTP`头
      * `method` 字符串，设置请求方法，如`GET`、`POST`
      * `path` 字符串，设置`URL`路径，如`/index.php?a=1&b=2`，必须以/作为开始
      * `cookies` 数组，设置`COOKIES`
      * `data` 设置请求的`body`，如果为字符串时将直接作为`RAW form-data`进行发送
      * `data` 为数组时，底层自动会打包为`x-www-form-urlencoded`格式的`POST`内容，并设置`Content-Type为application/x-www-form-urlencoded`
      * `pipeline` 布尔型，如果设置为`true`，发送完`$request`后，不关闭`stream`，可以继续写入数据内容

    * **pipeline**

      * 默认`send`方法在发送请求之后，会结束当前的`Http2 Stream`，启用`pipeline`后，底层会保持`stream`流，可以多次调用`write`方法，向服务器发送数据帧，请参考`write`方法。

### write()

向服务器发送更多数据帧，可以多次调用write向同一个stream写入数据帧。

```php
Swoole\Coroutine\Http2\Client->write(int $streamId, mixed $data, bool $end = false): bool
```

  * **参数** 

    * **`int $streamId`**
      * **功能**：流编号，由`send`方法返回
      * **默认值**：无
      * **其它值**：无

    * **`mixed $data`**
      * **功能**：数据帧的内容，可以为字符串或数组
      * **默认值**：无
      * **其它值**：无

    * **`bool $end`**
      * **功能**：是否关闭流
      * **默认值**：`false`
      * **其它值**：`true`

  * **使用示例**

```php
use Swoole\Http2\Request;
use Swoole\Coroutine\Http2\Client;
use function Swoole\Coroutine\run;

run(function () {
    $cli = new Client('127.0.0.1', 9518);
    $cli->set(['timeout' => 1]);
    var_dump($cli->connect());

    $req3 = new Request();
    $req3->path = "/index.php";
    $req3->headers = [
        'host' => "localhost",
        "user-agent" => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip',
    ];
    $req3->pipeline = true;
    $req3->method = "POST";
    $streamId = $cli->send($req3);
    $cli->write($streamId, ['int' => rand(1000, 9999)]);
    $cli->write($streamId, ['int' => rand(1000, 9999)]);
    //end stream
    $cli->write($streamId, ['int' => rand(1000, 9999), 'end' => true], true);
    var_dump($cli->recv());
    $cli->close();
});
```

!> 如果要使用`write`分段发送数据帧，必须在`send`请求时将`$request->pipeline`设置为`true`  
当发送`end`为`true`的数据帧之后，流将关闭，之后不能再调用`write`向此`stream`发送数据。

### recv()

接收请求。

!> 调用此方法时会产生[协程调度](/coroutine?id=协程调度)

```php
Swoole\Coroutine\Http2\Client->recv(float $timeout): Swoole\Http2\Response;
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：设置超时时间，参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：无
      * **其它值**：无

  * **返回值**

成功后返回 Swoole\Http2\Response 对象

```php
/**@var $resp Swoole\Http2\Response */
var_dump($resp->statusCode); // 服务器发送的Http状态码，如200、502等
var_dump($resp->headers); // 服务器发送的Header信息
var_dump($resp->cookies); // 服务器设置的COOKIE信息
var_dump($resp->set_cookie_headers); // 服务器端返回的原始COOKIE信息，包括了domain和path项
var_dump($resp->data); // 服务器发送的响应包体
```

!> Swoole版本 < [v4.0.4](/version/bc?id=_404) 时，`data`属性是`body`属性；Swoole版本 < [v4.0.3](/version/bc?id=_403) 时，`headers`和`cookies`为单数形式。

### read()

和`recv()`基本一致, 区别在于对于`pipeline`类型的响应, `read`可以分多次读取, 每次读取到部分的内容以节省内存或是尽快地接收到推送信息，而`recv`总是将所有帧拼接成一个完整响应后才会返回。

!> 调用此方法时会产生[协程调度](/coroutine?id=协程调度)

```php
Swoole\Coroutine\Http2\Client->read(float $timeout): Swoole\Http2\Response;
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：设置超时时间，参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：无
      * **其它值**：无

  * **返回值**

    成功后返回 Swoole\Http2\Response 对象

### goaway()

GOAWAY帧用于启动连接关闭或发出严重错误状态信号。

```php
Swoole\Coroutine\Http2\Client->goaway(int $error_code = SWOOLE_HTTP2_ERROR_NO_ERROR, string $debug_data): bool
```

### ping()

PING帧是一种机制，用于测量来自发送方的最小往返时间，以及确定空闲连接是否仍然有效。

```php
Swoole\Coroutine\Http2\Client->ping(): bool
```

### close()

关闭连接。

```php
Swoole\Coroutine\Http2\Client->close(): bool
```
