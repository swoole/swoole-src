# 协程FastCGI客户端

PHP-FPM使用了高效的二进制协议：`FastCGI协议`进行通讯, 通过FastCGI客户端，那么就可以直接与PHP-FPM服务进行交互而无需通过任何HTTP反向代理

[PHP源码目录](https://github.com/swoole/library/blob/master/src/core/Coroutine/FastCGI)

## 简单使用示例

[更多示例代码](https://github.com/swoole/library/tree/master/examples/fastcgi)

!> 以下示例代码需要在协程中调用

### 快速调用

```php
#greeter.php
echo 'Hello ' . ($_POST['who'] ?? 'World');
```

```php
echo \Swoole\Coroutine\FastCGI\Client::call(
    '127.0.0.1:9000', // FPM监听地址, 也可以是形如 unix:/tmp/php-cgi.sock 的unixsocket地址
    '/tmp/greeter.php', // 想要执行的入口文件
    ['who' => 'Swoole'] // 附带的POST信息
);
```

### PSR风格

```php
try {
    $client = new \Swoole\Coroutine\FastCGI\Client('127.0.0.1:9000', 9000);
    $request = (new \Swoole\FastCGI\HttpRequest())
        ->withScriptFilename(__DIR__ . '/greeter.php')
        ->withMethod('POST')
        ->withBody(['who' => 'Swoole']);
    $response = $client->execute($request);
    echo "Result: {$response->getBody()}\n";
} catch (\Swoole\Coroutine\FastCGI\Client\Exception $exception) {
    echo "Error: {$exception->getMessage()}\n";
}
```

### 复杂调用

```php
#var.php
var_dump($_SERVER);
var_dump($_GET);
var_dump($_POST);
```

```php
try {
    $client = new \Swoole\Coroutine\FastCGI\Client('127.0.0.1', 9000);
    $request = (new \Swoole\FastCGI\HttpRequest())
        ->withDocumentRoot(__DIR__)
        ->withScriptFilename(__DIR__ . '/var.php')
        ->withScriptName('var.php')
        ->withMethod('POST')
        ->withUri('/var?foo=bar&bar=char')
        ->withHeader('X-Foo', 'bar')
        ->withHeader('X-Bar', 'char')
        ->withBody(['foo' => 'bar', 'bar' => 'char']);
    $response = $client->execute($request);
    echo "Result: \n{$response->getBody()}";
} catch (\Swoole\Coroutine\FastCGI\Client\Exception $exception) {
    echo "Error: {$exception->getMessage()}\n";
}
```

### 一键代理WordPress

!> 此用法无生产意义, 生产中proxy可用于代理部分老API接口的HTTP请求到旧的FPM服务上 (而不是代理整站)

```php
use Swoole\Constant;
use Swoole\Coroutine\FastCGI\Proxy;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$documentRoot = '/var/www/html'; # WordPress项目根目录
$server = new Server('0.0.0.0', 80, SWOOLE_BASE); # 这里端口需要和WordPress配置一致, 一般不会特定指定端口, 就是80
$server->set([
    Constant::OPTION_WORKER_NUM => swoole_cpu_num() * 2,
    Constant::OPTION_HTTP_PARSE_COOKIE => false,
    Constant::OPTION_HTTP_PARSE_POST => false,
    Constant::OPTION_DOCUMENT_ROOT => $documentRoot,
    Constant::OPTION_ENABLE_STATIC_HANDLER => true,
    Constant::OPTION_STATIC_HANDLER_LOCATIONS => ['/wp-admin', '/wp-content', '/wp-includes'], #静态资源路径
]);
$proxy = new Proxy('127.0.0.1:9000', $documentRoot); # 建立代理对象
$server->on('request', function (Request $request, Response $response) use ($proxy) {
    $proxy->pass($request, $response); # 一键代理请求
});
$server->start();
```

## 方法

### call

静态方法, 直接创建一个新的客户端连接, 向FPM服务器发起请求并接收响应正文

!> FPM只支持短连接, 所以在通常情况下, 创建持久化对象没有太大的意义

```php
Swoole\Coroutine\FastCGI\Client::call(string $url, string $path, $data = '', float $timeout = -1): string
```

  * **参数** 

    * **`string $url`**
      * **功能**：FPM监听地址【如`127.0.0.1:9000`、`unix:/tmp/php-cgi.sock`等】
      * **默认值**：无
      * **其它值**：无

    * **`string $path`**
      * **功能**：想要执行的入口文件
      * **默认值**：无
      * **其它值**：无

    * **`$data`**
      * **功能**：附带的请求数据
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间【默认为 -1 表示永不超时】
      * **值单位**：秒【支持浮点型，如 1.5 表示 1s+500ms】
      * **默认值**：`-1`
      * **其它值**：无

  * **返回值** 

    * 返回服务器响应的主体内容(body)
    * 发生错误时将抛出`Swoole\Coroutine\FastCGI\Client\Exception`异常

### __construct

客户端对象的构造方法, 指定目标FPM服务器

```php
Swoole\Coroutine\FastCGI\Client::__construct(string $host, int $port = 0)
```

  * **参数** 

    * **`string $host`**
      * **功能**：目标服务器的地址【如`127.0.0.1`、`unix://tmp/php-fpm.sock`等】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：目标服务器端口【目标地址为UNIXSocket时无需传入】
      * **默认值**：无
      * **其它值**：无

### execute

执行请求, 返回响应

```php
Swoole\Coroutine\FastCGI\Client->execute(Request $request, float $timeout = -1): Response
```

  * **参数** 

    * **`Swoole\FastCGI\Request|Swoole\FastCGI\HttpRequest $request`**
      * **功能**：包含请求信息的对象, 通常使用`Swoole\FastCGI\HttpRequest`来模拟HTTP请求, 有特殊需求时才会使用FPM协议的原始请求类`Swoole\FastCGI\Request`
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间【默认为`-1`表示永不超时】
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`-1`
      * **其它值**：无

  * **返回值** 

    * 返回和请求对象类型对标的Response对象, 如`Swoole\FastCGI\HttpRequest`会返回`Swoole\FastCGI\HttpResponse对象`, 包含了FPM服务器的响应信息
    * 发生错误时将抛出`Swoole\Coroutine\FastCGI\Client\Exception`异常

## 相关请求/响应类

由于library无法引入PSR庞大的依赖实现和扩展加载总是在PHP代码执行之前, 所以相关的请求响应对象并没有继承PSR接口, 但尽量以PSR的风格实现以期开发者能够快速上手使用

FastCGI模拟HTTP请求响应的类的相关源码地址如下, 非常简单, 代码即文档:

[Swoole\FastCGI\HttpRequest](https://github.com/swoole/library/blob/master/src/core/FastCGI/HttpRequest.php)
[Swoole\FastCGI\HttpResponse](https://github.com/swoole/library/blob/master/src/core/FastCGI/HttpResponse.php)
