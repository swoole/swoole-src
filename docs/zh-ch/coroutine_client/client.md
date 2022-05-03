# 协程TCP/UDP客户端

`Coroutine\Client`提供了`TCP`、`UDP`、[unixSocket](/learn?id=什么是IPC)传输协议的[Socket客户端](/coroutine_client/socket)封装代码，使用时仅需`new Swoole\Coroutine\Client`即可。

* **实现原理**

    * `Coroutine\Client`的所有涉及网络请求的方法，`Swoole`都会进行[协程调度](/coroutine?id=协程调度)，业务层无需感知
    * 使用方法和[Client](/client)同步模式方法完全一致
    * `connect`超时设置同时作用于`Connect`、`Recv`和`Send` 超时

* **继承关系**

    * `Coroutine\Client`与[Client](/client)并不是继承关系，但`Client`提供的方法均可在`Coroutine\Client`中使用。请参考 [Swoole\Client](/client?id=方法)，在此不再赘述 。
    * 在`Coroutine\Client`中可以使用`set`方法设置[配置选项](/client?id=配置)，使用方法和与`Client->set`完全一致，对于使用有区别的函数，在`set()`函数小节会单独说明

* **使用示例**

```php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9501, 0.5))
    {
        echo "connect failed. Error: {$client->errCode}\n";
    }
    $client->send("hello world\n");
    echo $client->recv();
    $client->close();
});
```

* **协议处理**

协程客户端也支持长度和`EOF`协议处理，设置方法与 [Swoole\Client](/client?id=配置) 完全一致。

```php
$client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
$client->set(array(
    'open_length_check'     => true,
    'package_length_type'   => 'N',
    'package_length_offset' => 0, //第N个字节是包长度的值
    'package_body_offset'   => 4, //第几个字节开始计算长度
    'package_max_length'    => 2000000, //协议最大长度
));
```

### connect()

连接到远程服务器。

```php
Swoole\Coroutine\Client->connect(string $host, int $port, float $timeout = 0.5): bool
```

  * **参数** 

    * **`string $host`**
      * **功能**：远程服务器的地址【底层会自动进行协程切换解析域名为IP地址】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：远程服务器端口
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：网络IO的超时时间；包括`connect/send/recv`，超时发生时，连接会被自动`close`，参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`0.5s`
      * **其它值**：无

* **提示**

    * 如果连接失败，会返回`false`
    * 超时后返回，检查`$cli->errCode`为`110`

* **失败重试**

!> `connect`连接失败后，不可直接进行重连。必须使用`close`关闭已有`socket`，然后再进行`connect`重试。

```php
//连接失败
if ($cli->connect('127.0.0.1', 9501) == false) {
    //关闭已有socket
    $cli->close();
    //重试
    $cli->connect('127.0.0.1', 9501);
}
```

* **示例**

```php
if ($cli->connect('127.0.0.1', 9501)) {
    $cli->send('data');
} else {
    echo 'connect failed.';
}

if ($cli->connect('/tmp/rpc.sock')) {
    $cli->send('data');
} else {
    echo 'connect failed.';
}
```

### isConnected()

返回Client的连接状态

```php
Swoole\Coroutine\Client->isConnected(): bool
```

  * **返回值**

    * 返回`false`，表示当前未连接到服务器
    * 返回`true`，表示当前已连接到服务器
    
!> `isConnected`方法返回的是应用层状态，只表示`Client`执行了`connect`并成功连接到了`Server`，并且没有执行`close`关闭连接。`Client`可以执行`send`、`recv`、`close`等操作，但不能再次执行`connect` 。  
这不代表连接一定是可用的，当执行`send`或`recv`时仍然有可能返回错误，因为应用层无法获得底层`TCP`连接的状态，执行`send`或`recv`时应用层与内核发生交互，才能得到真实的连接可用状态。

### send()

发送数据。

```php
Swoole\Coroutine\Client->send(string $data): int|bool
```

  * **参数** 

    * **`string $data`**
    
      * **功能**：为发送的数据，必须为字符串类型，支持二进制数据
      * **默认值**：无
      * **其它值**：无

  * 发送成功返回写入`Socket`缓存区的字节数，底层会尽可能地将所有数据发出。如果返回的字节数与传入的`$data`长度不同，可能是`Socket`已被对端关闭，再下一次调用`send`或`recv`时将返回对应的错误码。

  * 发送失败返回false，可以使用 `$client->errCode` 获取错误原因。

### recv()

recv方法用于从服务器端接收数据。

```php
Swoole\Coroutine\Client->recv(float $timeout = 0): string|bool
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

    !> 设置超时，优先使用指定的参数，其次使用`set`方法中传入的`timeout`配置。发生超时的错误码为`ETIMEDOUT`

  * **返回值**

    * 设置了[通信协议](/client?id=协议解析)，`recv`会返回完整的数据，长度受限于[package_max_length](/server/setting?id=package_max_length)
    * 未设置通信协议，`recv`最大返回`64K`数据
    * 未设置通信协议返回原始的数据，需要`PHP`代码中自行实现网络协议的处理
    * `recv`返回空字符串表示服务端主动关闭连接，需要`close`
    * `recv`失败，返回`false`，检测`$client->errCode`获取错误原因，处理方式可参考下文的[完整示例](/coroutine_client/client?id=完整示例)

### close()

关闭连接。

!> `close`不存在阻塞，会立即返回。关闭操作没有协程切换。

```php
Swoole\Coroutine\Client->close(): bool
```

### peek()

窥视数据。

!> `peek`方法直接操作`socket`，因此不会引起[协程调度](/coroutine?id=协程调度)。

```php
Swoole\Coroutine\Client->peek(int $length = 65535): string
```

  * **提示**

    * `peek`方法仅用于窥视内核`socket`缓存区中的数据，不进行偏移。使用`peek`之后，再调用`recv`仍然可以读取到这部分数据
    * `peek`方法是非阻塞的，它会立即返回。当`socket`缓存区中有数据时，会返回数据内容。缓存区为空时返回`false`，并设置`$client->errCode`
    * 连接已被关闭`peek`会返回空字符串

### set()

设置客户端参数。

```php
Swoole\Coroutine\Client->set(array $settings): bool
```

  * **配置参数**

    * 请参考 [Swoole\Client](/client?id=set) 。

* **和[Swoole\Client](/client?id=set)的差异**
    
    协程客户端提供了更细粒度的超时控制。可以设置：
    
    * `timeout`：总超时，包括连接、发送、接收所有超时
    * `connect_timeout`：连接超时
    * `read_timeout`：接收超时
    * `write_timeout`：发送超时
    * 参考[客户端超时规则](/coroutine_client/init?id=超时规则)

* **示例**

```php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(array(
        'timeout' => 0.5,
        'connect_timeout' => 1.0,
        'write_timeout' => 10.0,
        'read_timeout' => 0.5,
    ));

    if (!$client->connect('127.0.0.1', 9501, 0.5))
    {
        echo "connect failed. Error: {$client->errCode}\n";
    }
    $client->send("hello world\n");
    echo $client->recv();
    $client->close();
});
```

### 完整示例

```php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9501, 0.5)) {
        echo "connect failed. Error: {$client->errCode}\n";
    }
    $client->send("hello world\n");
    while (true) {
        $data = $client->recv();
        if (strlen($data) > 0) {
            echo $data;
            $client->send(time() . PHP_EOL);
        } else {
            if ($data === '') {
                // 全等于空 直接关闭连接
                $client->close();
                break;
            } else {
                if ($data === false) {
                    // 可以自行根据业务逻辑和错误码进行处理，例如：
                    // 如果超时时则不关闭连接，其他情况直接关闭连接
                    if ($client->errCode !== SOCKET_ETIMEDOUT) {
                        $client->close();
                        break;
                    }
                } else {
                    $client->close();
                    break;
                }
            }
        }
        \Co::sleep(1);
    }
});
```
