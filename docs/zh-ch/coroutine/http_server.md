# HTTP服务器

?> 完全协程化的HTTP服务器实现，`Co\Http\Server`由于HTTP解析性能原因使用C++编写，因此并非由PHP编写的[Co\Server](/coroutine/server)的子类。

与 [Http\Server](/http_server) 的不同之处：

* 可以在运行时动态地创建、销毁
* 对连接的处理是在单独的子协程中完成，客户端连接的`Connect`、`Request`、`Response`、`Close`是完全串行的

!> 需要`v4.4.0`或更高版本

!> 若编译时[开启HTTP2](/environment?id=编译选项)，则默认会启用HTTP2协议支持，无需像`Swoole\Http\Server`一样配置[open_http2_protocol](/http_server?id=open_http2_protocol) (注：**v4.4.16以下版本HTTP2支持存在已知BUG, 请升级后使用**)

## 短命名

可使用`Co\Http\Server`短名。

## 方法

### __construct()

```php
Swoole\Coroutine\Http\Server::__construct(string $host, int $port = 0, bool $ssl = false, bool $reuse_port = false);
```

  * **参数** 

    * **`string $host`**
      * **功能**：监听的IP地址【若是本地UNIXSocket则应以形如`unix://tmp/your_file.sock`的格式填写 】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：监听端口 
      * **默认值**：0 (随机监听一个空闲端口)
      * **其它值**：0~65535

    * **`bool $ssl`**
      * **功能**：是否启用`SSL/TLS`隧道加密
      * **默认值**：false
      * **其它值**：true
      
    * **`bool $reuse_port`**
      * **功能**：是否启用端口复用特性，开启后多个服务可以共用一个端口
      * **默认值**：false
      * **其它值**：true

### handle()

注册回调函数以处理参数`$pattern`所指示路径下的HTTP请求。

```php
Swoole\Coroutine\Http\Server->handle(string $pattern, callable $fn): void
```

!> 必须在 [Server::start](/coroutine/server?id=start) 之前设置处理函数

  * **参数** 

    * **`string $pattern`**
      * **功能**：设置`URL`路径【如`/index.html`，注意这里不能传入`http://domain`】
      * **默认值**：无
      * **其它值**：无

    * **`callable $fn`**
      * **功能**：处理函数，用法参考`Swoole\Http\Server`中的[OnRequest](/http_server?id=on)回调，在此不再赘述
      * **默认值**：无
      * **其它值**：无      

      示例：

      ```php
      function callback(Swoole\Http\Request $req, Swoole\Http\Response $resp) {
          $resp->end("hello world");
      }
      ```

  * **提示**

    * 服务器在`Accept`（建立连接）成功后，会自动创建协程并接受`HTTP`请求
    * `$fn`是在新的子协程空间内执行，因此在函数内无需再次创建协程
    * 客户端支持[KeepAlive](/coroutine_client/http_client?id=keep_alive)，子协程会循环继续接受新的请求，而不退出
    * 客户端不支持`KeepAlive`，子协程会停止接受请求，并退出关闭连接

  * **注意**

    !> -`$pattern`设置相同路径时，新的设置会覆盖旧的设置；  
    -未设置/根路径处理函数并且请求的路径没有找到任何匹配的`$pattern`，Swoole将返回`404`错误；  
    -`$pattern`使用字符串匹配的方法，不支持通配符和正则，不区分大小写，匹配算法是前缀匹配，例如：url是`/test111`会匹配到`/test`这个规则，匹配到即跳出匹配忽略后面的配置；  
    -推荐设置/根路径处理函数，并在回调函数中使用`$request->server['request_uri']`进行请求路由。

### start()

?> **启动服务器。** 

```php
Swoole\Coroutine\Http\Server->start();
```

### shutdown()

?> **终止服务器。** 

```php
Swoole\Coroutine\Http\Server->shutdown();
```

## 完整示例

```php
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

run(function () {
    $server = new Server('127.0.0.1', 9502, false);
    $server->handle('/', function ($request, $response) {
        $response->end("<h1>Index</h1>");
    });
    $server->handle('/test', function ($request, $response) {
        $response->end("<h1>Test</h1>");
    });
    $server->handle('/stop', function ($request, $response) use ($server) {
        $response->end("<h1>Stop</h1>");
        $server->shutdown();
    });
    $server->start();
});
```
