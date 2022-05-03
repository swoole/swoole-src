# Coroutine\System

系统相关`API`的协程封装。此模块在`v4.4.6`正式版本后可用。大部分`API`基于`AIO`线程池实现。

!> `v4.4.6`以前的版本, 请使用`Co`短名或`Swoole\Coroutine`调用, 如: `Co::sleep` 或 `Swoole\Coroutine::sleep`  
`v4.4.6`及以后版本官方**推荐使用**`Co\System::sleep`或`Swoole\Coroutine\System::sleep`  
此修改旨在规范命名空间, 但同时也保证向下兼容 (也就是说`v4.4.6`版本以前的写法也是可以的, 无需修改)

## 方法

### statvfs()

获取文件系统信息。

!> Swoole版本 >= v4.2.5 可用

```php
Swoole\Coroutine\System::statvfs(string $path): array|false
```

  * **参数** 

    * **`string $path`**
      * **功能**：文件系统挂载的目录【如`/`，可以使用df和`mount -l`命令获取】
      * **默认值**：无
      * **其它值**：无

  * **使用示例**

    ```php
    Swoole\Coroutine\run(function () {
        var_dump(Swoole\Coroutine\System::statvfs('/'));
    });
    
    // array(11) {
    //   ["bsize"]=>
    //   int(4096)
    //   ["frsize"]=>
    //   int(4096)
    //   ["blocks"]=>
    //   int(61068098)
    //   ["bfree"]=>
    //   int(45753580)
    //   ["bavail"]=>
    //   int(42645728)
    //   ["files"]=>
    //   int(15523840)
    //   ["ffree"]=>
    //   int(14909927)
    //   ["favail"]=>
    //   int(14909927)
    //   ["fsid"]=>
    //   int(1002377915335522995)
    //   ["flag"]=>
    //   int(4096)
    //   ["namemax"]=>
    //   int(255)
    // }
    ```

### fread()

协程方式读取文件。

```php
Swoole\Coroutine\System::fread(resource $handle, int $length = 0): string|false
```

!> `v4.0.4`以下版本`fread`方法不支持非文件类型的`stream`，如`STDIN`、`Socket`，请勿使用`fread`操作此类资源。  
`v4.0.4`以上版本`fread`方法支持了非文件类型的`stream`资源，底层会自动根据`stream`类型选择使用`AIO`线程池或[EventLoop](/learn?id=什么是eventloop)实现。

  * **参数** 

    * **`resource $handle`**
      * **功能**：文件句柄【必须是`fopen`打开的文件类型`stream`资源】
      * **默认值**：无
      * **其它值**：无

    * **`int $length`**
      * **功能**：读取的长度【默认为`0`，表示读取文件的全部内容】
      * **默认值**：`0`
      * **其它值**：无

  * **返回值** 

    * 读取成功返回字符串内容，读取失败返回`false`

  * **使用示例**  

    ```php
    $fp = fopen(__FILE__, "r");
    Swoole\Coroutine\run(function () use ($fp)
    {
        $r = Swoole\Coroutine\System::fread($fp);
        var_dump($r);
    });
    ```

### fwrite()

协程方式向文件写入数据。

```php
Swoole\Coroutine\System::fwrite(resource $handle, string $data, int $length = 0): int|false
```

!> `v4.0.4`以下版本`fwrite`方法不支持非文件类型的`stream`，如`STDIN`、`Socket`，请勿使用`fwrite`操作此类资源。  
`v4.0.4`以上版本`fwrite`方法支持了非文件类型的`stream`资源，底层会自动根据`stream`类型选择使用`AIO`线程池或[EventLoop](/learn?id=什么是eventloop)实现。

  * **参数** 

    * **`resource $handle`**
      * **功能**：文件句柄【必须是`fopen`打开的文件类型`stream`资源】
      * **默认值**：无
      * **其它值**：无

    * **`string $data`**
      * **功能**：要写入的数据内容【可以是文本或二进制数据】
      * **默认值**：无
      * **其它值**：无

    * **`int $length`**
      * **功能**：读取的长度【默认为`0`，表示写入`$data`的全部内容，`$length`必须小于`$data`的长度】
      * **默认值**：`0`
      * **其它值**：无

  * **返回值** 

    * 写入成功返回数据长度，读取失败返回`false`

  * **使用示例**  

    ```php
    $fp = fopen(__DIR__ . "/test.data", "a+");
    Swoole\Coroutine\run(function () use ($fp)
    {
        $r = Swoole\Coroutine\System::fwrite($fp, "hello world\n", 5);
        var_dump($r);
    });
    ```

### fgets()

协程方式按行读取文件内容。

底层使用了`php_stream`缓存区，默认大小为`8192`字节，可使用`stream_set_chunk_size`设置缓存区尺寸。

```php
Swoole\Coroutine\System::fgets(resource $handle): string|false
```

!> `fgets`函数仅可用于文件类型的`stream`资源，Swoole版本 >= `v4.4.4` 可用

  * **参数** 

    * **`resource $handle`**
      * **功能**：文件句柄【必须是`fopen`打开的文件类型`stream`资源】
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

    * 读取到`EOL`（`\r`或`\n`）将返回一行数据，包括`EOL`
    * 未读取到`EOL`，但内容长度超过`php_stream`缓存区`8192`字节，将返回`8192`字节的数据，不包含`EOL`
    * 达到文件末尾`EOF`时，返回空字符串，可用`feof`判断文件是否已读完
    * 读取失败返回`false`，使用[swoole_last_error](/functions?id=swoole_last_error)函数获取错误码

  * **使用示例**  

    ```php
    $fp = fopen(__DIR__ . "/defer_client.php", "r");
    Swoole\Coroutine\run(function () use ($fp)
    {
        $r = Swoole\Coroutine\System::fgets($fp);
        var_dump($r);
    });
    ```

### readFile()

协程方式读取文件。

```php
Swoole\Coroutine\System::readFile(string $filename): string|false
```

  * **参数** 

    * **`string $filename`**
      * **功能**：文件名
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

    * 读取成功返回字符串内容，读取失败返回`false`，可使用[swoole_last_error](/functions?id=swoole_last_error)获取错误信息
    * `readFile`方法没有尺寸限制，读取的内容会存放在内存中，因此读取超大文件时可能会占用过多内存

  * **使用示例**  

    ```php
    $filename = __DIR__ . "/defer_client.php";
    Swoole\Coroutine\run(function () use ($filename)
    {
        $r = Swoole\Coroutine\System::readFile($filename);
        var_dump($r);
    });
    ```

### writeFile()

协程方式写入文件。

```php
Swoole\Coroutine\System::writeFile(string $filename, string $fileContent, int $flags): bool
```

  * **参数** 

    * **`string $filename`**
      * **功能**：文件名【必须有可写权限，文件不存在会自动创建。打开文件失败会立即返回`false`】
      * **默认值**：无
      * **其它值**：无

    * **`string $fileContent`**
      * **功能**：写入到文件的内容【最大可写入`4M`】
      * **默认值**：无
      * **其它值**：无

    * **`int $flags`**
      * **功能**：写入的选项【默认会清空当前文件内容，可以使用`FILE_APPEND`表示追加到文件末尾】
      * **默认值**：无
      * **其它值**：无

  * **返回值** 

    * 写入成功返回`true`
    * 写入失败返回`false`

  * **使用示例**  

    ```php
    $filename = __DIR__ . "/defer_client.php";
    Swoole\Coroutine\run(function () use ($filename)
    {
        $w = Swoole\Coroutine\System::writeFile($filename, "hello swoole!");
        var_dump($w);
    });
    ```

### sleep()

进入等待状态。

相当于`PHP`的`sleep`函数，不同的是`Coroutine::sleep`是[协程调度](/coroutine?id=协程调度)器实现的，底层会`yield`当前协程，让出时间片，并添加一个异步定时器，当超时时间到达时重新`resume`当前协程，恢复运行。

使用`sleep`接口可以方便地实现超时等待功能。

```php
Swoole\Coroutine\System::sleep(float $seconds): void
```

  * **参数** 

    * **`float $seconds`**
      * **功能**：睡眠的时间【必须大于`0`，最大不得超过一天时间（`86400`秒）】
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：无
      * **其它值**：无

  * **使用示例**  

    ```php
    $server = new Swoole\Http\Server("127.0.0.1", 9502);

    $server->on('Request', function($request, $response) {
        //等待200ms后向浏览器发送响应
        Swoole\Coroutine\System::sleep(0.2);
        $response->end("<h1>Hello Swoole!</h1>");
    });

    $server->start();
    ```

### exec()

执行一条shell指令。底层自动进行[协程调度](/coroutine?id=协程调度)。

```php
Swoole\Coroutine\System::exec(string $cmd): array
```

  * **参数** 

    * **`string $cmd`**
      * **功能**：要执行的`shell`指令
      * **默认值**：无
      * **其它值**：无

  * **返回值**

    * 执行失败返回`false`，执行成功返回数组，包含了进程退出的状态码、信号、输出内容。

    ```php
    array(
        'code'   => 0,  // 进程退出的状态码
        'signal' => 0,  // 信号
        'output' => '', // 输出内容
    );
    ```

  * **使用示例**  

    ```php
    Swoole\Coroutine\run(function() {
        $ret = Swoole\Coroutine\System::exec("md5sum ".__FILE__);
    });
    ```

### gethostbyname()

将域名解析为IP。基于同步的线程池模拟实现，底层自动进行[协程调度](/coroutine?id=协程调度)。

```php
Swoole\Coroutine\System::gethostbyname(string $domain, int $family = AF_INET, float $timeout = -1): string|false
```

  * **参数** 

    * **`string $domain`**
      * **功能**：域名
      * **默认值**：无
      * **其它值**：无

    * **`int $family`**
      * **功能**：域族【`AF_INET`表示返回`IPv4`地址，使用`AF_INET6`时返回`IPv6`地址】
      * **默认值**：`AF_INET`
      * **其它值**：`AF_INET6`

    * **`float $timeout`**
      * **功能**：超时时间
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

  * **返回值**

    * 成功返回域名对应的`IP`地址，失败返回`false`，可使用[swoole_last_error](/functions?id=swoole_last_error)获取错误信息

    ```php
    array(
        'code'   => 0,  // 进程退出的状态码
        'signal' => 0,  // 信号
        'output' => '', // 输出内容
    );
    ```

  * **扩展**

    * **超时控制**

      `$timeout`参数可以控制协程等待的超时时间，在规定的时间内未返回结果，协程会立即返回`false`并继续向下执行。底层实现中会将该异步任务标记为`cancel`，`gethostbyname`还是会在`AIO`线程池中继续执行。
      
      可修改`/etc/resolv.conf`设置`gethostbyname`和`getaddrinfo`底层`C`函数的超时时间。具体请参考 [设置 DNS 解析超时和重试](/learn_other?id=设置dns解析超时和重试)

  * **使用示例**  

    ```php
    Swoole\Coroutine\run(function () {
        $ip = Swoole\Coroutine\System::gethostbyname("www.baidu.com", AF_INET, 0.5);
        echo $ip;
    });
    ```

### getaddrinfo()

进行DNS解析，查询域名对应的`IP`地址。

与`gethostbyname`不同，`getaddrinfo`支持更多参数设置，而且会返回多个`IP`结果。

```php
Swoole\Coroutine\System::getaddrinfo(string $domain, int $family = AF_INET, int $socktype = SOCK_STREAM, int $protocol = STREAM_IPPROTO_TCP, string $service = null, float $timeout = -1): array|false
```

  * **参数** 

    * **`string $domain`**
      * **功能**：域名
      * **默认值**：无
      * **其它值**：无

    * **`int $family`**
      * **功能**：域族【`AF_INET`表示返回`IPv4`地址，使用`AF_INET6`时返回`IPv6`地址】
      * **默认值**：无
      * **其它值**：无
      
      !> 其他参数设置请参考`man getaddrinfo`文档

    * **`int $socktype`**
      * **功能**：协议类型
      * **默认值**：`SOCK_STREAM`
      * **其它值**：`SOCK_DGRAM`、`SOCK_RAW`

    * **`int $protocol`**
      * **功能**：协议
      * **默认值**：`STREAM_IPPROTO_TCP`
      * **其它值**：`STREAM_IPPROTO_UDP`、`STREAM_IPPROTO_STCP`、`STREAM_IPPROTO_TIPC`、`0`

    * **`string $service`**
      * **功能**：
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：超时时间
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

  * **返回值**

    * 成功返回多个`IP`地址组成的数组，失败返回`false`

  * **使用示例**  

    ```php
    Swoole\Coroutine\run(function () {
        $ips = Swoole\Coroutine\System::getaddrinfo("www.baidu.com");
        var_dump($ips);
    });
    ```

### dnsLookup()

域名地址查询。

与`Coroutine\System::gethostbyname`不同，`Coroutine\System::dnsLookup`是直接基于`UDP`客户端网络通信实现的，而不是使用`libc`提供的`gethostbyname`函数。

!> Swoole 版本 >= `v4.4.3` 可用，底层会读取`/etc/resolve.conf`获取`DNS`服务器地址，目前仅支持`AF_INET(IPv4)`域名解析。Swoole 版本 >= `v4.7` 时可使用第三个参数来支持`AF_INET6(IPv6)`

```php
Swoole\Coroutine\System::dnsLookup(string $domain, float $timeout = 5, int $type = AF_INET): string|false
```

  * **参数** 

    * **`string $domain`**
      * **功能**：域名
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：超时时间
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`5`
      * **其它值**：无

    * **`int $type`**
        * **值单位**：秒，最小精度为毫秒（`0.001`秒）
        * **默认值**：`AF_INET`
        * **其它值**：`AF_INET6`

    !> `$type`参数在 Swoole 版本 >= `v4.7` 可用。

  * **返回值**

    * 解析成功返回对应的IP地址
    * 失败返回`false`，可以使用[swoole_last_error](/functions?id=swoole_last_error)获取错误信息

  * **常见错误**

    * `SWOOLE_ERROR_DNSLOOKUP_RESOLVE_FAILED`：此域名无法解析，查询失败
    * `SWOOLE_ERROR_DNSLOOKUP_RESOLVE_TIMEOUT`：解析超时，DNS服务器可能存在故障，无法在规定的时间内返回结果

  * **使用示例**  

    ```php
    Swoole\Coroutine\run(function () {
        $ip = Swoole\Coroutine\System::dnsLookup("www.baidu.com");
        echo $ip;
    });
    ```

### wait()

对应原有的[Process::wait](/process/process?id=wait)，不同的是此API是协程版本, 会造成协程挂起，可替换 `Swoole\Process::wait` 和 `pcntl_wait` 函数。

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Coroutine\System::wait(float $timeout = -1): array|false
```

* **参数** 

    * **`float $timeout`**
      * **功能**：超时时间，负数表示永不超时
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

* **返回值**

  * 操作成功会返回一个数组包含子进程的`PID`、退出状态码、被哪种信号`KILL`
  * 失败返回`false`

!> 每个子进程启动后，父进程必须都要派遣一个协程调用`wait()`(或`waitPid()`)进行回收，否则子进程会变成僵尸进程，会浪费操作系统的进程资源。  
如果使用了协程，必须是先创建进程，进程里面再开协程。而不是反过来，否则就是带着协程 fork 情况会非常复杂，导致底层很难处理。

* **示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$process = new Process(function () {
    echo 'Hello Swoole';
});
$process->start();

Coroutine\run(function () use ($process) {
    $status = System::wait();
    assert($status['pid'] === $process->pid);
    var_dump($status);
});
```

### waitPid()

和上述wait方法基本一致, 不同的是此API可以指定等待特定的进程

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Coroutine\System::waitPid(int $pid, float $timeout = -1): array|false
```

* **参数** 

    * **`int $pid`**
      * **功能**：进程id
      * **默认值**：`-1` (表示任意进程, 此时等价于wait方法)
      * **其它值**：任意自然数

    * **`float $timeout`**
      * **功能**：超时时间，负数表示永不超时
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

* **返回值**

  * 操作成功会返回一个数组包含子进程的`PID`、退出状态码、被哪种信号`KILL`
  * 失败返回`false`

!> 每个子进程启动后，父进程必须都要派遣一个协程调用`wait()`(或`waitPid()`)进行回收，否则子进程会变成僵尸进程，会浪费操作系统的进程资源。

* **示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$process = new Process(function () {
    echo 'Hello Swoole';
});
$process->start();

Coroutine\run(function () use ($process) {
    $status = System::waitPid($process->pid);
    var_dump($status);
});
```

### waitSignal()

协程版本的信号监听器, 会阻塞当前协程直到信号触发，可替换 `Swoole\Process::signal` 和 `pcntl_signal` 函数。

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Coroutine\System::waitSignal(int $signo, float $timeout = -1): bool
```

  * **参数** 

    * **`int $signo`**
      * **功能**：信号类型
      * **默认值**：无
      * **其它值**：SIG系列常量, 如`SIGTERM`, `SIGKILL`等

    * **`float $timeout`**
      * **功能**：超时时间，负数表示永不超时
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

  * **返回值**

    * 收到信号返回`true`
    * 超时未收到信号返回`false`

  * **示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$process = new Process(function () {
    Coroutine\run(function () {
        $bool = System::waitSignal(SIGUSR1);
        var_dump($bool);
    });
});
$process->start();
sleep(1);
$process::kill($process->pid, SIGUSR1);
```

### waitEvent()

协程版本的信号监听器, 会阻塞当前协程直到信号触发。等待 IO 事件，可替换 `swoole_event` 相关函数。

!> Swoole版本 >= `v4.5` 可用

```php
Swoole\Coroutine\System::waitEvent(mixed $socket, int $events = SWOOLE_EVENT_READ, float $timeout = -1): int | false
```

* **参数** 

    * **`mixed $socket`**
      * **功能**：文件描述符 (任何可以转化为fd的类型, 如Socket对象, 资源等等)
      * **默认值**：无
      * **其它值**：无

    * **`int $events`**
      * **功能**：事件类型
      * **默认值**：`SWOOLE_EVENT_READ`
      * **其它值**：`SWOOLE_EVENT_WRITE` 或 `SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE`

    * **`float $timeout`**
      * **功能**：超时时间，负数表示永不超时
      * **值单位**：秒，最小精度为毫秒（`0.001`秒）
      * **默认值**：`-1`
      * **其它值**：无

* **返回值**

  * 返回触发的事件类型的和(可能是多个位), 和参数`$events`传入的值有关
  * 失败返回`false`，可以使用[swoole_last_error](/functions?id=swoole_last_error)获取错误信息

* **示例**

> 同步阻塞的代码通过该API即可变为协程非阻塞

```php
use Swoole\Coroutine;

Coroutine\run(function () {
    $client = stream_socket_client('tcp://www.qq.com:80', $errno, $errstr, 30);
    $events = Coroutine::waitEvent($client, SWOOLE_EVENT_READ | SWOOLE_EVENT_WRITE);
    assert($events === SWOOLE_EVENT_WRITE);
    fwrite($client, "GET / HTTP/1.1\r\nHost: www.qq.com\r\n\r\n");
    $events = Coroutine::waitEvent($client, SWOOLE_EVENT_READ);
    assert($events === SWOOLE_EVENT_READ);
    $response = fread($client, 8192);
    echo $response;
});
```