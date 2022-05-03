# TCP服务器

?> `Swoole\Coroutine\Server` 是一个完全[协程](/coroutine)化的类，用于创建协程`TCP`服务器，支持TCP和[unixSocket](/learn?id=什么是IPC)类型。

与[Server](/server/tcp_init)模块不同之处：

* 动态创建销毁，在运行时可以动态监听端口，也可以动态关闭服务器
* 处理连接的过程是完全同步的，程序可以顺序处理`Connect`、`Receive`、`Close`事件

!> 在4.4以上版本中可用

## 短命名

可使用`Co\Server`短名。

## 方法

### __construct()

?> **构造方法。** 

```php
Swoole\Coroutine\Server::__construct(string $host, int $port = 0, bool $ssl = false, bool $reuse_port = false);
```

  * **参数** 

    * **`string $host`**
      * **功能**：监听的地址
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：监听的端口【如果为0将由操作系统随机分配一个端口】
      * **默认值**：无
      * **其它值**：无

    * **`bool $ssl`**
      * **功能**：是否开启SSL加密
      * **默认值**：`false`
      * **其它值**：`true`

    * **`bool $reuse_port`**
      * **功能**：是否开启端口重用，效果和[此节](/server/setting?id=enable_reuse_port)的配置一样
      * **默认值**：`false`
      * **其它值**：`true`
      * **版本影响**：Swoole版本 >= v4.4.4

  * **提示**

    * **$host 参数支持 3 种格式**

      * `0.0.0.0/127.0.0.1`: IPv4地址
      * `::/::1`: IPv6地址
      * `unix:/tmp/test.sock`: [UnixSocket](/learn?id=什么是IPC)地址

    * **异常**

      * 参数错误、绑定地址和端口失败、`listen`失败时将抛出`Swoole\Exception`异常。

### set()

?> **设置协议处理参数。** 

```php
Swoole\Coroutine\Server->set(array $options);
```

  * **配置参数**

    * 参数`$options`必须为一维的关联索引数组，与 [setprotocol](/coroutine_client/socket?id=setprotocol) 方法接受的配置项完全一致。

    !> 必须在 [start()](/coroutine/server?id=start) 方法之前设置参数

    * **长度协议**

    ```php
    $server = new Swoole\Coroutine\Server('127.0.0.1', $port, $ssl);
    $server->set([
      'open_length_check' => true,
      'package_max_length' => 1024 * 1024,
      'package_length_type' => 'N',
      'package_length_offset' => 0,
      'package_body_offset' => 4,
    ]);
    ```

    * **SSL证书设置**

    ```php
    $server->set([
      'ssl_cert_file' => dirname(__DIR__) . '/ssl/server.crt',
      'ssl_key_file' => dirname(__DIR__) . '/ssl/server.key',
    ]);
    ```

### handle()

?> **设置连接处理函数。** 

!> 必须在 [start()](/coroutine/server?id=start) 之前设置处理函数

```php
Swoole\Coroutine\Server->handle(callable $fn);
```

  * **参数** 

    * **`callable $fn`**
      * **功能**：设置连接处理函数
      * **默认值**：无
      * **其它值**：无
      
  * **示例** 

    ```php
    $server->handle(function (Swoole\Coroutine\Server\Connection $conn) {
        while (true) {
            $data = $conn->recv();
        }
    });
    ```

    !> -服务器在`Accept`(建立连接)成功后，会自动创建[协程](/coroutine?id=协程调度)并执行`$fn` ；  
    -`$fn`是在新的子协程空间内执行，因此在函数内无需再次创建协程；  
    -`$fn`接受一个参数，类型为[Swoole\Coroutine\Server\Connection](/coroutine/server?id=coroutineserverconnection)对象;  
    -可以使用[exportSocket()](/coroutine/server?id=exportsocket)得到当前连接的Socket对象

### shutdown()

?> **终止服务器。** 

?> 底层支持`start`和`shutdown`多次调用

```php
Swoole\Coroutine\Server->shutdown(): bool
```

### start()

?> **启动服务器。** 

```php
Swoole\Coroutine\Server->start(): bool
```

  * **返回值**

    * 启动失败会返回`false`，并设置`errCode`属性
    * 启动成功将进入循环，`Accept`连接
    * `Accept`(建立连接)后会创建一个新的协程，并在协程中调用handle方法指定的函数

  * **错误处理**

    * 当`Accept`(建立连接)发生`Too many open file`错误、或者无法创建子协程时，将暂停`1`秒然后再继续`Accept`
    * 发生错误时，`start()`方法将返回，错误信息将会以`Warning`的形式报出。

## 对象

### Coroutine\Server\Connection

`Swoole\Coroutine\Server\Connection`对象提供了四个方法：
 
#### recv()

接收数据，如果设置了协议处理，将每次返回完整的包

```php
function recv(float $timeout = 0)
```

#### send()

发送数据

```php
function send(string $data)
```

#### close()

关闭连接

```php
function close(): bool
```

#### exportSocket()

得到当前连接的Socket对象。可调用更多底层的方法，请参考 [Swoole\Coroutine\Socket](/coroutine_client/socket)

```php
function exportSocket(): Swoole\Coroutine\Socket
```

## 完整示例

```php
use Swoole\Process;
use Swoole\Coroutine;
use Swoole\Coroutine\Server\Connection;

//多进程管理模块
$pool = new Process\Pool(2);
//让每个OnWorkerStart回调都自动创建一个协程
$pool->set(['enable_coroutine' => true]);
$pool->on('workerStart', function ($pool, $id) {
    //每个进程都监听9501端口
    $server = new Swoole\Coroutine\Server('127.0.0.1', 9501, false, true);

    //收到15信号关闭服务
    Process::signal(SIGTERM, function () use ($server) {
        $server->shutdown();
    });

    //接收到新的连接请求 并自动创建一个协程
    $server->handle(function (Connection $conn) {
        while (true) {
            //接收数据
            $data = $conn->recv(1);

            if ($data === '' || $data === false) {
                $errCode = swoole_last_error();
                $errMsg = socket_strerror($errCode);
                echo "errCode: {$errCode}, errMsg: {$errMsg}\n";
                $conn->close();
                break;
            }

            //发送数据
            $conn->send('hello');

            Coroutine::sleep(1);
        }
    });

    //开始监听端口
    $server->start();
});
$pool->start();
```

!> 如果在Cygwin环境下运行请修改为单进程。`$pool = new Swoole\Process\Pool(1);`