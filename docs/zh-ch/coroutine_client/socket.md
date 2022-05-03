# Coroutine\Socket

`Swoole\Coroutine\Socket`模块相比[协程风格服务端](/server/co_init)和[协程客户端](/coroutine_client/init)相关模块`Socket`可以实现更细粒度的一些`IO`操作。

!> 可使用`Co\Socket`短命名简化类名。此模块比较底层，使用者最好有Socket编程经验。

## 完整示例

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

run(function () {
    $socket = new Coroutine\Socket(AF_INET, SOCK_STREAM, 0);

    $retval = $socket->connect('127.0.0.1', 9601);
    while ($retval)
    {
        $n = $socket->send('hello');
        var_dump($n);

        $data = $socket->recv();
        var_dump($data);

        //发生错误或对端关闭连接，本端也需要关闭
        if ($data === '' || $data === false) {
            echo "errCode: {$socket->errCode}\n";
            $socket->close();
            break;
        }

        Coroutine::sleep(1.0);
    }

    var_dump($retval, $socket->errCode, $socket->errMsg);
});
```

## 协程调度

`Coroutine\Socket`模块提供的`IO`操作接口均为同步编程风格，底层自动使用[协程调度](/coroutine?id=协程调度)器实现[异步IO](/learn?id=同步io异步io)。

## 错误码

在执行`socket`相关系统调用时，可能返回-1错误，底层会设置`Coroutine\Socket->errCode`属性为系统错误编号`errno`，请参考响应的`man`文档。如`$socket->accept()`返回错误时，`errCode`含义可以参考`man accept`中列出的错误码文档。

## 属性

### fd

`socket`对应的文件描述符`ID`

### errCode

错误码

## 方法

### __construct()

构造方法。构造`Coroutine\Socket`对象。

```php
Swoole\Coroutine\Socket::__construct(int $domain, int $type, int $protocol);
```

!> 详情可参见`man socket`文档。

  * **参数** 

    * **`int $domain`**
      * **功能**：协议域【可使用`AF_INET`、`AF_INET6`、`AF_UNIX`】
      * **默认值**：无
      * **其它值**：无

    * **`int $type`**
      * **功能**：类型【可使用`SOCK_STREAM`、`SOCK_DGRAM`、`SOCK_RAW`】
      * **默认值**：无
      * **其它值**：无

    * **`int $protocol`**
      * **功能**：协议【可使用`IPPROTO_TCP`、`IPPROTO_UDP`、`IPPROTO_STCP`、`IPPROTO_TIPC`，`0`】
      * **默认值**：无
      * **其它值**：无

!> 构造方法会调用`socket`系统调用创建一个`socket`句柄。调用失败时会抛出`Swoole\Coroutine\Socket\Exception`异常。并设置`$socket->errCode`属性。可根据该属性的值得到系统调用失败的原因。

### getOption()

获取配置。

!> 此方法对应`getsockopt`系统调用, 详情可参见`man getsockopt`文档。  
此方法和`sockets`扩展的`socket_get_option`功能等价, 可以参见[PHP文档](https://www.php.net/manual/zh/function.socket-get-option.php)。

!> Swoole版本 >= v4.3.2

```php
Swoole\Coroutine\Socket->getOption(int $level, int $optname): mixed
```

  * **参数** 

    * **`int $level`**
      * **功能**：指定选项所在的协议级别
      * **默认值**：无
      * **其它值**：无

      !> 例如，要在套接字级别检索选项，将使用`SOL_SOCKET`的 `level` 参数。  
      可以通过指定该级别的协议编号来使用其他级别，例如`TCP`。可以使用[getprotobyname](https://www.php.net/manual/zh/function.getprotobyname.php)函数找到协议号。

    * **`int $optname`**
      * **功能**：可用的套接字选项与[socket_get_option()](https://www.php.net/manual/zh/function.socket-get-option.php)函数的套接字选项相同
      * **默认值**：无
      * **其它值**：无

### setOption()

设置配置。

!> 此方法对应`setsockopt`系统调用, 详情可参见`man setsockopt`文档。此方法和`sockets`扩展的`socket_set_option`功能等价, 可以参见[PHP文档](https://www.php.net/manual/zh/function.socket-set-option.php)

!> Swoole版本 >= v4.3.2

```php
Swoole\Coroutine\Socket->setOption(int $level, int $optname, mixed $optval): bool
```

  * **参数** 

    * **`int $level`**
      * **功能**：指定选项所在的协议级别
      * **默认值**：无
      * **其它值**：无

      !> 例如，要在套接字级别检索选项，将使用`SOL_SOCKET`的 `level` 参数。  
      可以通过指定该级别的协议编号来使用其他级别，例如`TCP`。可以使用[getprotobyname](https://www.php.net/manual/zh/function.getprotobyname.php)函数找到协议号。

    * **`int $optname`**
      * **功能**：可用的套接字选项与[socket_get_option()](https://www.php.net/manual/zh/function.socket-get-option.php)函数的套接字选项相同
      * **默认值**：无
      * **其它值**：无

    * **`int $optval`**
      * **功能**：选项的值 【可以是`int`、`bool`、`string`、`array`。根据`level`和`optname`决定。】
      * **默认值**：无
      * **其它值**：无

### setProtocol()

使`socket`获得协议处理能力，可以配置是否开启`SSL`加密传输和解决 [TCP数据包边界问题](/learn?id=tcp数据包边界问题) 等

!> Swoole版本 >= v4.3.2

```php
Swoole\Coroutine\Socket->setProtocol(array $settings): bool
```

  * **$settings 支持的参数**

参数 | 类型
---|---
open_ssl | bool
ssl_cert_file | string
ssl_key_file | string
open_eof_check | bool
open_eof_split | bool
open_mqtt_protocol | bool
open_fastcgi_protocol | bool
open_length_check | bool
package_eof | string
package_length_type | string
package_length_offset | int
package_body_offset | int
package_length_func | callable
package_max_length | int

!> 上述所有参数的意义和[Server->set()](/server/setting?id=open_eof_check)完全一致，在此不再赘述。

  * **示例**

```php
$socket->setProtocol([
    'open_length_check'     => true,
    'package_max_length'    => 1024 * 1024,
    'package_length_type'   => 'N',
    'package_length_offset' => 0,
    'package_body_offset'   => 4,
]);
```

### bind()

绑定地址和端口。

!> 此方法没有`IO`操作，不会引起协程切换

```php
Swoole\Coroutine\Socket->bind(string $address, int $port = 0): bool
```

  * **参数** 

    * **`string $address`**
      * **功能**：绑定的地址【如`0.0.0.0`、`127.0.0.1`】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：：绑定的端口【默认为`0`，系统会随机绑定一个可用端口，可使用[getsockname](/coroutine_client/socket?id=getsockname)方法得到系统分配的`port`】
      * **默认值**：`0`
      * **其它值**：无

  * **返回值** 

    * 绑定成功返回`true`
    * 绑定失败返回`false`，请检查`errCode`属性获取失败原因

### listen()

监听`Socket`。

!> 此方法没有`IO`操作，不会引起协程切换

```php
Swoole\Coroutine\Socket->listen(int $backlog = 0): bool
```

  * **参数** 

    * **`int $backlog`**
      * **功能**：监听队列的长度【默认为`0`，系统底层使用`epoll`实现了异步`IO`，不存在阻塞，因此`backlog`的重要程度并不高】
      * **默认值**：`0`
      * **其它值**：无

      !> 如果应用中存在阻塞或耗时逻辑，`accept`接受连接不及时，新创建的连接就会堆积在`backlog`监听队列中，如超出`backlog`长度，服务就会拒绝新的连接进入

  * **返回值** 

    * 绑定成功返回`true`
    * 绑定失败返回`false`，请检查`errCode`属性获取失败原因

  * **内核参数** 

    `backlog`的最大值受限于内核参数`net.core.somaxconn`, 而`Linux`中可以工具`sysctl`来动态调整所有的`kernel`参数。动态调整是内核参数值修改后即时生效。但是这个生效仅限于`OS`层面，必须重启应用才能真正生效, 命令`sysctl -a`会显示所有的内核参数及值。

    ```shell
    sysctl -w net.core.somaxconn=2048
    ```

    以上命令将内核参数`net.core.somaxconn`的值改成了`2048`。这样的改动虽然可以立即生效，但是重启机器后会恢复默认值。为了永久保留改动，需要修改`/etc/sysctl.conf`，增加`net.core.somaxconn=2048`然后执行命令`sysctl -p`生效。

### accept()

接受客户端发起的连接。

调用此方法会立即挂起当前协程，并加入[EventLoop](/learn?id=什么是eventloop)监听可读事件，当`Socket`可读有到来的连接时自动唤醒该协程，并返回对应客户端连接的`Socket`对象。

!> 该方法必须在使用`listen`方法后使用，适用于`Server`端。

```php
Swoole\Coroutine\Socket->accept(float $timeout = 0): Coroutine\Socket|false;
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：设置超时【设置超时参数后，底层会设置定时器，在规定的时间没有客户端连接到来，`accept`方法将返回`false`】
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 超时或`accept`系统调用报错时返回`false`，可使用`errCode`属性获取错误码，其中超时错误码为`ETIMEDOUT`
    * 成功返回客户端连接的`socket`，类型同样为`Swoole\Coroutine\Socket`对象。可对其执行`send`、`recv`、`close`等操作

  * **示例**

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

run(function () {
$socket = new Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$socket->bind('127.0.0.1', 9601);
$socket->listen(128);

    while(true) {
        echo "Accept: \n";
        $client = $socket->accept();
        if ($client === false) {
            var_dump($socket->errCode);
        } else {
            var_dump($client);
        }
    }
});
```

### connect()

连接到目标服务器。

调用此方法会发起异步的`connect`系统调用，并挂起当前协程，底层会监听可写，当连接完成或失败后，恢复该协程。

该方法适用于`Client`端，支持`IPv4`、`IPv6`、[unixSocket](/learn?id=什么是IPC)。

```php
Swoole\Coroutine\Socket->connect(string $host, int $port = 0, float $timeout = 0): bool
```

  * **参数** 

    * **`string $host`**
      * **功能**：目标服务器的地址【如`127.0.0.1`、`192.168.1.100`、`/tmp/php-fpm.sock`、`www.baidu.com`等，可以传入`IP`地址、`Unix Socket`路径或域名。若为域名，底层会自动进行异步的`DNS`解析，不会引起阻塞】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：目标服务器端口【`Socket`的`domain`为`AF_INET`、`AF_INET6`时必须设置端口】
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间【底层会设置定时器，在规定的时间内未能建立连接，`connect`将返回`false`】
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 超时或`connect`系统调用报错时返回`false`，可使用`errCode`属性获取错误码，其中超时错误码为`ETIMEDOUT`
    * 成功返回`true`

### checkLiveness()

通过系统调用检查连接是否存活 (在异常断开时无效, 仅能侦测到对端正常close下的连接断开)

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Coroutine\Socket->checkLiveness(): bool
```

  * **返回值** 

    * 连接存活时返回`true`, 否则返回`false`

### send()

向对端发送数据。

!> `send`方法会立即执行`send`系统调用发送数据，当`send`系统调用返回错误`EAGAIN`时，底层将自动监听可写事件，并挂起当前协程，等待可写事件触发时，重新执行`send`系统调用发送数据，并唤醒该协程。  

!> 如果`send`过快，`recv`过慢最终会导致操作系统缓冲区写满，当前协程挂起在send方法，可以适当调大缓冲区，[/proc/sys/net/core/wmem_max和SO_SNDBUF](https://stackoverflow.com/questions/21856517/whats-the-practical-limit-on-the-size-of-single-packet-transmitted-over-domain)

```php
Swoole\Coroutine\Socket->send(string $data, float $timeout = 0): int|false
```

  * **参数** 

    * **`string $data`**
      * **功能**：要发送的数据内容【可以为文本或二进制数据】
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 发送成功返回写入的字节数，**请注意实际写入的数据可能小于`$data`参数的长度**，应用层代码需要对比返回值与`strlen($data)`是否相等来判断是否发送完成
    * 发送失败返回`false`，并设置`errCode`属性

### sendAll()

向对端发送数据。与`send`方法不同的是, `sendAll`会尽可能完整地发送数据, 直到成功发送全部数据或遇到错误中止。

!> `sendAll`方法会立即执行多次`send`系统调用发送数据，当`send`系统调用返回错误`EAGAIN`时，底层将自动监听可写事件，并挂起当前协程，等待可写事件触发时，重新执行`send`系统调用发送数据, 直到数据发送完成或遇到错误, 唤醒对应协程。  

!> Swoole版本 >= v4.3.0

```php
Swoole\Coroutine\Socket->sendAll(string $data, float $timeout = 0) : int | false;
```

  * **参数** 

    * **`string $data`**
      * **功能**：要发送的数据内容【可以为文本或二进制数据】
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * `sendAll`会保证数据全部发送成功，但是`sendAll`期间对端有可能将连接断开，此时可能发送成功了部分数据，返回值会返回这个成功数据的长度，应用层代码需要对比返回值与`strlen($data)`是否相等来判断是否发送完成，根据业务需求是否需要续传。
    * 发送失败返回`false`，并设置`errCode`属性

### peek()

窥视读缓冲区中的数据, 相当于系统调用中的`recv(length, MSG_PEEK)`。

!> `peek`是立即完成的, 不会挂起协程, 但有一次系统调用开销

```php
Swoole\Coroutine\Socket->peek(int $length = 65535): string|false
```

  * **参数** 

    * **`int $length`**
      * **功能**：指定用于拷贝窥视到的数据的内存大小 (注意：这里会分配内存, 过大的长度可能会导致内存耗尽)
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

    * 窥视成功返回数据
    * 窥视失败返回`false`，并设置`errCode`属性

### recv()

接收数据。

!> `recv`方法会立即挂起当前协程并监听可读事件，等待对端发送数据后，可读事件触发时，执行`recv`系统调用获取`socket`缓存区中的数据，并唤醒该协程。

```php
Swoole\Coroutine\Socket->recv(int $length = 65535, float $timeout = 0): string|false
```

  * **参数** 

    * **`int $length`**
      * **功能**：指定用于接收数据的内存大小 (注意：这里会分配内存, 过大的长度可能会导致内存耗尽)
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 接收成功返回实际数据
    * 接收失败返回`false`，并设置`errCode`属性
    * 接收超时，错误码为`ETIMEDOUT`

!> 返回值不一定等于预期长度, 需要自行检查该次调用接收数据的长度, 如需要保证单次调用获取到指定长度的数据, 请使用`recvAll`方法或自行循环获取  
TCP数据包边界问题请参考`setProtocol()`方法，或者用`sendto()`;

### recvAll()

接收数据。与`recv`不同的是, `recvAll`会尽可能完整地接收响应长度的数据, 直到接收完成或遇到错误失败。

!> `recvAll`方法会立即挂起当前协程并监听可读事件，等待对端发送数据后，可读事件触发时，执行`recv`系统调用获取`socket`缓存区中的数据, 重复该行为直到接收到指定长度的数据或遇到错误终止，并唤醒该协程。

!> Swoole版本 >= v4.3.0

```php
Swoole\Coroutine\Socket->recvAll(int $length = 65535, float $timeout = 0): string|false
```

  * **参数** 

    * **`int $length`**
      * **功能**：期望接收到的数据大小 (注意：这里会分配内存, 过大的长度可能会导致内存耗尽)
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 接收成功返回实际数据, 并且返回的字符串长度和参数长度一致
    * 接收失败返回`false`，并设置`errCode`属性
    * 接收超时，错误码为`ETIMEDOUT`

### readVector()

分段接收数据。

!> `readVector`方法会立即执行`readv`系统调用读取数据，当`readv`系统调用返回错误`EAGAIN`时，底层将自动监听可读事件，并挂起当前协程，等待可读事件触发时，重新执行`readv`系统调用读取数据，并唤醒该协程。  

!> Swoole版本 >= v4.5.7

```php
Swoole\Coroutine\Socket->readVector(array $io_vector, float $timeout = 0): array|false
```

  * **参数** 

    * **`array $io_vector`**
      * **功能**：期望接收到的分段数据大小
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值**

    * 接收成功返回的分段数据
    * 接收失败返回空数组，并设置`errCode`属性
    * 接收超时，错误码为`ETIMEDOUT`

  * **示例** 

```php
$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
// 如果对端发来了helloworld
$ret = $socket->readVector([5, 5]);
// 那么，$ret是['hello', 'world']
```

### readVectorAll()

分段接收数据。

!> `readVectorAll`方法会立即执行多次`readv`系统调用读取数据，当`readv`系统调用返回错误`EAGAIN`时，底层将自动监听可读事件，并挂起当前协程，等待可读事件触发时，重新执行`readv`系统调用读取数据, 直到数据读取完成或遇到错误, 唤醒对应协程。

!> Swoole版本 >= v4.5.7

```php
Swoole\Coroutine\Socket->readVectorAll(array $io_vector, float $timeout = 0): array|false
```

  * **参数** 

    * **`array $io_vector`**
      * **功能**：期望接收到的分段数据大小
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值**

    * 接收成功返回的分段数据
    * 接收失败返回空数组，并设置`errCode`属性
    * 接收超时，错误码为`ETIMEDOUT`

### writeVector()

分段发送数据。

!> `writeVector`方法会立即执行`writev`系统调用发送数据，当`writev`系统调用返回错误`EAGAIN`时，底层将自动监听可写事件，并挂起当前协程，等待可写事件触发时，重新执行`writev`系统调用发送数据，并唤醒该协程。  

!> Swoole版本 >= v4.5.7

```php
Swoole\Coroutine\Socket->writeVector(array $io_vector, float $timeout = 0): int|false
```

  * **参数** 

    * **`array $io_vector`**
      * **功能**：期望发送的分段数据
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值**

    * 发送成功返回写入的字节数，**请注意实际写入的数据可能小于`$io_vector`参数的总长度**，应用层代码需要对比返回值与`$io_vector`参数的总长度是否相等来判断是否发送完成
    * 发送失败返回`false`，并设置`errCode`属性

  * **示例** 

```php
$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
// 此时会按照数组里面的顺序发送给对端，实际上就是发送helloworld
$socket->writeVector(['hello', 'world']);
```

### writeVectorAll()

向对端发送数据。与`writeVector`方法不同的是, `writeVectorAll`会尽可能完整地发送数据, 直到成功发送全部数据或遇到错误中止。

!> `writeVectorAll`方法会立即执行多次`writev`系统调用发送数据，当`writev`系统调用返回错误`EAGAIN`时，底层将自动监听可写事件，并挂起当前协程，等待可写事件触发时，重新执行`writev`系统调用发送数据, 直到数据发送完成或遇到错误, 唤醒对应协程。

!> Swoole版本 >= v4.5.7

```php
Swoole\Coroutine\Socket->writeVectorAll(array $io_vector, float $timeout = 0): int|false
```

  * **参数** 

    * **`array $io_vector`**
      * **功能**：期望发送的分段数据
      * **值单位**：字节
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值**

    * `writeVectorAll`会保证数据全部发送成功，但是`writeVectorAll`期间对端有可能将连接断开，此时可能发送成功了部分数据，返回值会返回这个成功数据的长度，应用层代码需要对比返回值与`$io_vector`参数的总长度是否相等来判断是否发送完成，根据业务需求是否需要续传。
    * 发送失败返回`false`，并设置`errCode`属性

  * **示例** 

```php
$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
// 此时会按照数组里面的顺序发送给对端，实际上就是发送helloworld
$socket->writeVectorAll(['hello', 'world']);
```

### recvPacket()

对于已通过`setProtocol`方法设置协议的Socket对象, 可调用此方法接收一个完整的协议数据包

!> Swoole版本 >= v4.4.0

```php
Swoole\Coroutine\Socket->recvPacket(float $timeout = 0): string|false
```

  * **参数** 
    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
      * **其它值**：无

  * **返回值** 

    * 接收成功返回一个完整协议数据包
    * 接收失败返回`false`，并设置`errCode`属性
    * 接收超时，错误码为`ETIMEDOUT`

### recvLine()

用于解决 [socket_read](https://www.php.net/manual/en/function.socket-read.php) 兼容性问题

```php
Swoole\Coroutine\Socket->recvLine(int $length = 65535, float $timeout = 0): string|false
```

### recvWithBuffer()

用于解决使用 `recv(1)` 逐字节接收时产生大量系统调用问题

```php
Swoole\Coroutine\Socket->recvWithBuffer(int $length = 65535, float $timeout = 0): string|false
```

### recvfrom()

接收数据，并设置来源主机的地址和端口。用于`SOCK_DGRAM`类型的`socket`。

!> 此方法会引起[协程调度](/coroutine?id=协程调度)，底层会立即挂起当前协程，并监听可读事件。可读事件触发，收到数据后执行`recvfrom`系统调用获取数据包。

```php
Swoole\Coroutine\Socket->recvfrom(array &$peer, float $timeout = 0): string|false
```

* **参数**

    * **`array $peer`**
        * **功能**：对端地址和端口，引用类型。【函数成功返回时会设置为数组，包括`address`和`port`两个元素】
        * **默认值**：无
        * **其它值**：无

    * **`float $timeout`**
        * **功能**：设置超时时间【在规定的时间内未返回数据，`recvfrom`方法会返回`false`】
        * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
        * **默认值**：参考[客户端超时规则](/coroutine_client/init?id=超时规则)
        * **其它值**：无

* **返回值**

    * 成功接收数据，返回数据内容，并设置`$peer`为数组
    * 失败返回`false`，并设置`errCode`属性，不修改`$peer`的内容

* **示例**

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

run(function () {
    $socket = new Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9601);
    while (true) {
        $peer = null;
        $data = $socket->recvfrom($peer);
        echo "[Server] recvfrom[{$peer['address']}:{$peer['port']}] : $data\n";
        $socket->sendto($peer['address'], $peer['port'], "Swoole: $data");
    }
});
```

### sendto()

向指定的地址和端口发送数据。用于`SOCK_DGRAM`类型的`socket`。

!> 此方法没有[协程调度](/coroutine?id=协程调度)，底层会立即调用`sendto`向目标主机发送数据。此方法不会监听可写，`sendto`可能会因为缓存区已满而返会`false`，需要自行处理，或者使用`send`方法。

```php
Swoole\Coroutine\Socket->sendto(string $address, int $port, string $data): int|false
```

  * **参数** 

    * **`string $address`**
      * **功能**：目标主机的`IP`地址或[unixSocket](/learn?id=什么是IPC)路径【`sendto`不支持域名，使用`AF_INET`或`AF_INET6`时，必须传入合法的`IP`地址，否则发送会返回失败】
      * **默认值**：无
      * **其它值**：无

    * **`int $port`**
      * **功能**：目标主机的端口【发送广播时可以为`0`】
      * **默认值**：无
      * **其它值**：无

    * **`string $data`**
      * **功能**：发送的数据【可以为文本或二进制内容，请注意`SOCK_DGRAM`发送包的最大长度为`64K`】
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

    * 发送成功返回发送的字节数
    * 发送失败返回`false`，并设置`errCode`属性

  * **示例** 

```php
$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
$socket->sendto('127.0.0.1', 9601, 'Hello');
```

### getsockname()

获取socket的地址和端口信息。

!> 此方法没有[协程调度](/coroutine?id=协程调度)开销。

```php
Swoole\Coroutine\Socket->getsockname(): array|false
```

  * **返回值** 

    * 调用成功返回，包含`address`和`port`的数组
    * 调用失败返回`false`，并设置`errCode`属性

### getpeername()

获取`socket`的对端地址和端口信息，仅用于`SOCK_STREAM`类型有连接的`socket`。

?> 此方法没有[协程调度](/coroutine?id=协程调度)开销。

```php
Swoole\Coroutine\Socket->getpeername(): array|false
```

  * **返回值** 

    * 调用成功返回，包含`address`和`port`的数组
    * 调用失败返回`false`，并设置`errCode`属性

### close()

关闭`Socket`。

!> `Swoole\Coroutine\Socket`对象析构时如果会自动执行`close`，此方法没有[协程调度](/coroutine?id=协程调度)开销。

```php
Swoole\Coroutine\Socket->close(): bool
```

  * **返回值** 

    * 关闭成功返回`true`
    * 失败返回`false`
    
### isClosed()

`Socket`是否已关闭。

```php
Swoole\Coroutine\Socket->isClosed(): bool
```

## 常量

等价于`sockets`扩展提供的常量, 且不会与`sockets`扩展产生冲突

!> 在不同系统下的值会有出入, 以下代码仅为示例, 请勿使用其值

```php
define ('AF_UNIX', 1);
define ('AF_INET', 2);

/**
 * Only available if compiled with IPv6 support.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('AF_INET6', 10);
define ('SOCK_STREAM', 1);
define ('SOCK_DGRAM', 2);
define ('SOCK_RAW', 3);
define ('SOCK_SEQPACKET', 5);
define ('SOCK_RDM', 4);
define ('MSG_OOB', 1);
define ('MSG_WAITALL', 256);
define ('MSG_CTRUNC', 8);
define ('MSG_TRUNC', 32);
define ('MSG_PEEK', 2);
define ('MSG_DONTROUTE', 4);

/**
 * Not available on Windows platforms.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('MSG_EOR', 128);

/**
 * Not available on Windows platforms.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('MSG_EOF', 512);
define ('MSG_CONFIRM', 2048);
define ('MSG_ERRQUEUE', 8192);
define ('MSG_NOSIGNAL', 16384);
define ('MSG_DONTWAIT', 64);
define ('MSG_MORE', 32768);
define ('MSG_WAITFORONE', 65536);
define ('MSG_CMSG_CLOEXEC', 1073741824);
define ('SO_DEBUG', 1);
define ('SO_REUSEADDR', 2);

/**
 * This constant is only available in PHP 5.4.10 or later on platforms that
 * support the <b>SO_REUSEPORT</b> socket option: this
 * includes Mac OS X and FreeBSD, but does not include Linux or Windows.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SO_REUSEPORT', 15);
define ('SO_KEEPALIVE', 9);
define ('SO_DONTROUTE', 5);
define ('SO_LINGER', 13);
define ('SO_BROADCAST', 6);
define ('SO_OOBINLINE', 10);
define ('SO_SNDBUF', 7);
define ('SO_RCVBUF', 8);
define ('SO_SNDLOWAT', 19);
define ('SO_RCVLOWAT', 18);
define ('SO_SNDTIMEO', 21);
define ('SO_RCVTIMEO', 20);
define ('SO_TYPE', 3);
define ('SO_ERROR', 4);
define ('SO_BINDTODEVICE', 25);
define ('SOL_SOCKET', 1);
define ('SOMAXCONN', 128);

/**
 * Used to disable Nagle TCP algorithm.
 * Added in PHP 5.2.7.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('TCP_NODELAY', 1);
define ('PHP_NORMAL_READ', 1);
define ('PHP_BINARY_READ', 2);
define ('MCAST_JOIN_GROUP', 42);
define ('MCAST_LEAVE_GROUP', 45);
define ('MCAST_BLOCK_SOURCE', 43);
define ('MCAST_UNBLOCK_SOURCE', 44);
define ('MCAST_JOIN_SOURCE_GROUP', 46);
define ('MCAST_LEAVE_SOURCE_GROUP', 47);
define ('IP_MULTICAST_IF', 32);
define ('IP_MULTICAST_TTL', 33);
define ('IP_MULTICAST_LOOP', 34);
define ('IPV6_MULTICAST_IF', 17);
define ('IPV6_MULTICAST_HOPS', 18);
define ('IPV6_MULTICAST_LOOP', 19);
define ('IPV6_V6ONLY', 27);

/**
 * Operation not permitted.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPERM', 1);

/**
 * No such file or directory.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOENT', 2);

/**
 * Interrupted system call.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EINTR', 4);

/**
 * I/O error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EIO', 5);

/**
 * No such device or address.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENXIO', 6);

/**
 * Arg list too long.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_E2BIG', 7);

/**
 * Bad file number.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADF', 9);

/**
 * Try again.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EAGAIN', 11);

/**
 * Out of memory.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOMEM', 12);

/**
 * Permission denied.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EACCES', 13);

/**
 * Bad address.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EFAULT', 14);

/**
 * Block device required.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTBLK', 15);

/**
 * Device or resource busy.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBUSY', 16);

/**
 * File exists.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EEXIST', 17);

/**
 * Cross-device link.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EXDEV', 18);

/**
 * No such device.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENODEV', 19);

/**
 * Not a directory.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTDIR', 20);

/**
 * Is a directory.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EISDIR', 21);

/**
 * Invalid argument.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EINVAL', 22);

/**
 * File table overflow.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENFILE', 23);

/**
 * Too many open files.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EMFILE', 24);

/**
 * Not a typewriter.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTTY', 25);

/**
 * No space left on device.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOSPC', 28);

/**
 * Illegal seek.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ESPIPE', 29);

/**
 * Read-only file system.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EROFS', 30);

/**
 * Too many links.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EMLINK', 31);

/**
 * Broken pipe.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPIPE', 32);

/**
 * File name too long.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENAMETOOLONG', 36);

/**
 * No record locks available.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOLCK', 37);

/**
 * Function not implemented.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOSYS', 38);

/**
 * Directory not empty.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTEMPTY', 39);

/**
 * Too many symbolic links encountered.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ELOOP', 40);

/**
 * Operation would block.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EWOULDBLOCK', 11);

/**
 * No message of desired type.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOMSG', 42);

/**
 * Identifier removed.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EIDRM', 43);

/**
 * Channel number out of range.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ECHRNG', 44);

/**
 * Level 2 not synchronized.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EL2NSYNC', 45);

/**
 * Level 3 halted.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EL3HLT', 46);

/**
 * Level 3 reset.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EL3RST', 47);

/**
 * Link number out of range.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ELNRNG', 48);

/**
 * Protocol driver not attached.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EUNATCH', 49);

/**
 * No CSI structure available.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOCSI', 50);

/**
 * Level 2 halted.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EL2HLT', 51);

/**
 * Invalid exchange.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADE', 52);

/**
 * Invalid request descriptor.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADR', 53);

/**
 * Exchange full.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EXFULL', 54);

/**
 * No anode.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOANO', 55);

/**
 * Invalid request code.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADRQC', 56);

/**
 * Invalid slot.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADSLT', 57);

/**
 * Device not a stream.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOSTR', 60);

/**
 * No data available.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENODATA', 61);

/**
 * Timer expired.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ETIME', 62);

/**
 * Out of streams resources.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOSR', 63);

/**
 * Machine is not on the network.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENONET', 64);

/**
 * Object is remote.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EREMOTE', 66);

/**
 * Link has been severed.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOLINK', 67);

/**
 * Advertise error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EADV', 68);

/**
 * Srmount error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ESRMNT', 69);

/**
 * Communication error on send.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ECOMM', 70);

/**
 * Protocol error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPROTO', 71);

/**
 * Multihop attempted.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EMULTIHOP', 72);

/**
 * Not a data message.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADMSG', 74);

/**
 * Name not unique on network.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTUNIQ', 76);

/**
 * File descriptor in bad state.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EBADFD', 77);

/**
 * Remote address changed.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EREMCHG', 78);

/**
 * Interrupted system call should be restarted.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ERESTART', 85);

/**
 * Streams pipe error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ESTRPIPE', 86);

/**
 * Too many users.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EUSERS', 87);

/**
 * Socket operation on non-socket.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTSOCK', 88);

/**
 * Destination address required.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EDESTADDRREQ', 89);

/**
 * Message too long.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EMSGSIZE', 90);

/**
 * Protocol wrong type for socket.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPROTOTYPE', 91);
define ('SOCKET_ENOPROTOOPT', 92);

/**
 * Protocol not supported.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPROTONOSUPPORT', 93);

/**
 * Socket type not supported.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ESOCKTNOSUPPORT', 94);

/**
 * Operation not supported on transport endpoint.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EOPNOTSUPP', 95);

/**
 * Protocol family not supported.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EPFNOSUPPORT', 96);

/**
 * Address family not supported by protocol.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EAFNOSUPPORT', 97);
define ('SOCKET_EADDRINUSE', 98);

/**
 * Cannot assign requested address.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EADDRNOTAVAIL', 99);

/**
 * Network is down.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENETDOWN', 100);

/**
 * Network is unreachable.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENETUNREACH', 101);

/**
 * Network dropped connection because of reset.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENETRESET', 102);

/**
 * Software caused connection abort.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ECONNABORTED', 103);

/**
 * Connection reset by peer.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ECONNRESET', 104);

/**
 * No buffer space available.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOBUFS', 105);

/**
 * Transport endpoint is already connected.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EISCONN', 106);

/**
 * Transport endpoint is not connected.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOTCONN', 107);

/**
 * Cannot send after transport endpoint shutdown.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ESHUTDOWN', 108);

/**
 * Too many references: cannot splice.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ETOOMANYREFS', 109);

/**
 * Connection timed out.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ETIMEDOUT', 110);

/**
 * Connection refused.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ECONNREFUSED', 111);

/**
 * Host is down.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EHOSTDOWN', 112);

/**
 * No route to host.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EHOSTUNREACH', 113);

/**
 * Operation already in progress.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EALREADY', 114);

/**
 * Operation now in progress.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EINPROGRESS', 115);

/**
 * Is a named type file.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EISNAM', 120);

/**
 * Remote I/O error.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EREMOTEIO', 121);

/**
 * Quota exceeded.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EDQUOT', 122);

/**
 * No medium found.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_ENOMEDIUM', 123);

/**
 * Wrong medium type.
 * @link http://php.net/manual/en/sockets.constants.php
 */
define ('SOCKET_EMEDIUMTYPE', 124);
define ('IPPROTO_IP', 0);
define ('IPPROTO_IPV6', 41);
define ('SOL_TCP', 6);
define ('SOL_UDP', 17);
define ('IPV6_UNICAST_HOPS', 16);
define ('IPV6_RECVPKTINFO', 49);
define ('IPV6_PKTINFO', 50);
define ('IPV6_RECVHOPLIMIT', 51);
define ('IPV6_HOPLIMIT', 52);
define ('IPV6_RECVTCLASS', 66);
define ('IPV6_TCLASS', 67);
define ('SCM_RIGHTS', 1);
define ('SCM_CREDENTIALS', 2);
define ('SO_PASSCRED', 16);
```
