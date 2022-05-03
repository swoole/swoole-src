# Process\Pool

进程池，基于[Swoole\Server](/server/init)的Manager管理进程模块实现。可管理多个工作进程。该模块的核心功能为进程管理，相比`Process`实现多进程，`Process\Pool`更加简单，封装层次更高，开发者无需编写过多代码即可实现进程管理功能，配合[Co\Server](/coroutine/server?id=完整示例)可以创建纯协程风格的，能利用多核CPU的服务端程序。

## 常量

常量 | 说明
---|---
SWOOLE_IPC_MSGQUEUE | 系统[消息队列](/learn?id=什么是IPC)通信
SWOOLE_IPC_SOCKET | SOCKET通信
SWOOLE_IPC_UNIXSOCK | [UnixSocket](/learn?id=什么是IPC)通信(v4.4+)

## 协程支持

在`v4.4.0`版本中增加了对协程的支持，请参考 [Process\Pool::__construct](/process/process_pool?id=__construct)

## 使用示例

```php
use Swoole\Process;
use Swoole\Coroutine;

$pool = new Process\Pool(5);
$pool->set(['enable_coroutine' => true]);
$pool->on('WorkerStart', function (Process\Pool $pool, $workerId) {
    /** 当前是 Worker 进程 */
    static $running = true;
    Process::signal(SIGTERM, function () use (&$running) {
        $running = false;
        echo "TERM\n";
    });
    echo("[Worker #{$workerId}] WorkerStart, pid: " . posix_getpid() . "\n");
    while ($running) {
        Coroutine::sleep(1);
        echo "sleep 1\n";
    }
});
$pool->on('WorkerStop', function (\Swoole\Process\Pool $pool, $workerId) {
    echo("[Worker #{$workerId}] WorkerStop\n");
});
$pool->start();
```

## 方法

### __construct()

构造方法。

```php
Swoole\Process\Pool::__construct(int $worker_num, int $ipc_type = SWOOLE_IPC_NONE, int $msgqueue_key = 0, bool $enable_coroutine = false);
```

* **参数** 

  * **`int $worker_num`**
    * **功能**：指定工作进程的数量
    * **默认值**：无
    * **其它值**：无

  * **`int $ipc_type`**
    * **功能**：进程间通信的模式【默认为`0`表示不使用任何进程间通信特性】
    * **默认值**：`SWOOLE_IPC_NONE`
    * **其它值**：无

    !> -设置为`0`时必须设置`onWorkerStart`回调，并且必须在`onWorkerStart`中实现循环逻辑，当`onWorkerStart`函数退出时工作进程会立即退出，之后会由`Manager`进程重新拉起进程；  
    -设置为`SWOOLE_IPC_MSGQUEUE`表示使用系统消息队列通信，可设置`$msgqueue_key`指定消息队列的`KEY`，未设置消息队列`KEY`，将申请私有队列；  
    -设置为`SWOOLE_IPC_SOCKET`表示使用`Socket`进行通信，需要使用[listen](/process/process_pool?id=listen)方法指定监听的地址和端口；  
    -设置为`SWOOLE_IPC_UNIXSOCK`表示使用[unixSocket](/learn?id=什么是IPC)进行通信，协程模式下使用，**强烈推荐用此种方式进程间通讯**，具体用法见下文；  
    -使用非`0`设置时，必须设置`onMessage`回调，`onWorkerStart`变更为可选。

  * **`int $msgqueue_key`**
    * **功能**：消息队列的 `key`
    * **默认值**：`0`
    * **其它值**：无

  * **`bool $enable_coroutine`**
    * **功能**：是否开启协程支持【使用协程后将无法设置`onMessage`回调】
    * **默认值**：`false`
    * **其它值**：`true`

* **协程模式**
    
在`v4.4.0`版本中`Process\Pool`模块增加了对协程的支持，可以配置第`4`个参数为`true`来启用。启用协程后底层会在`onWorkerStart`时自动创建一个协程和[协程容器](/coroutine/scheduler)，在回调函数中可直接使用协程相关`API`，例如：

```php
$pool = new Swoole\Process\Pool(1, SWOOLE_IPC_NONE, 0, true);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    while (true) {
        Co::sleep(0.5);
        echo "hello world\n";
    }
});

$pool->start();
```

开启协程后Swoole会禁止设置`onMessage`事件回调，需要进程间通讯的话需要将第二个设置为`SWOOLE_IPC_UNIXSOCK`表示使用[unixSocket](/learn?id=什么是IPC)进行通信，然后使用`$pool->getProcess()->exportSocket()`导出[Coroutine\Socket](/coroutine_client/socket)对象，实现`Worker`进程间通信。例如：

 ```php
$pool = new Swoole\Process\Pool(2, SWOOLE_IPC_UNIXSOCK, 0, true);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    $process = $pool->getProcess(0);
    $socket = $process->exportSocket();
    if ($workerId == 0) {
        echo $socket->recv();
        $socket->send("hello proc1\n");
        echo "proc0 stop\n";
    } else {
        $socket->send("hello proc0\n");
        echo $socket->recv();
        echo "proc1 stop\n";
        $pool->shutdown();
    }
});

$pool->start();
 ```

!> 具体用法可以参考[Co\Socket](/coroutine_client/socket)和[Process](/process/process?id=exportsocket)相关章节。

* **消息队列**

    在使用`SWOOLE_IPC_MSGQUEUE`时可使用`sysvmsg`扩展提供的消息队列`API`向工作进程投递任务。

    * 必须传入`Pool`创建时使用的`key`
    * 底层不支持`msg_send`的第二个参数`mtype`，请传入任意非`0`值

```php
$q = msg_get_queue($key);
foreach (range(1, 100) as $i) {
    $data = json_encode(['data' => base64_encode(random_bytes(1024)), 'id' => uniqid(), 'index' => $i,]);
    msg_send($q, $i, $data, false);
}
```

### set()

设置参数。

```php
Swoole\Process\Pool->set(array $settings)
```

可以使用`enable_coroutine`来控制是否启用协程，和构造函数的第四个参数作用一致。

```php
Swoole\Process\Pool->set(['enable_coroutine' => true]);
```

!> Swoole版本 >= v4.4.4 可用

### on()

设置进程池回调函数。

```php
Swoole\Process\Pool->on(string $event, callable $function);
```

* **参数** 

  * **`string $event`**
    * **功能**：指定事件
    * **默认值**：无
    * **其它值**：无

  * **`callable $function`**
    * **功能**：回调函数
    * **默认值**：无
    * **其它值**：无

* **事件**

  * **onWorkerStart** 子进程启动

  ```php
  /**
  * @param \Swoole\Process\Pool $pool Pool对象
  * @param int $workerId   WorkerId当前工作进程的编号，底层会对子进程进行标号
  */
  function onWorkerStart(Swoole\Process\Pool $pool, int $workerId) {
      echo "Worker#{$workerId} is started\n";
  }
  ```

  * **onWorkerStop** 子进程结束

  与`onWorkerStart`参数一致。

  * **onMessage** 消息接收

  !> 收到外部投递的消息。 一次连接只能投递一次消息, 类似于`PHP-FPM`的短连接机制

  ```php
  /**
  * @param \Swoole\Process\Pool $pool Pool对象
  * @param string $data 消息数据内容
  */
  function onMessage(Swoole\Process\Pool $pool, string $data) {
      var_dump($data);
  }
  ```

### listen()

监听`SOCKET`，必须在`$ipc_mode = SWOOLE_IPC_SOCKET`时才能使用。

```php
Swoole\Process\Pool->listen(string $host, int $port = 0, int $backlog = 2048): bool
```

* **参数** 

  * **`string $host`**
    * **功能**：监听的地址【支持`TCP`和[unixSocket](/learn?id=什么是IPC)两种类型。`127.0.0.1`表示监听`TCP`地址，需要指定`$port`。`unix:/tmp/php.sock`监听[unixSocket](/learn?id=什么是IPC)地址】
    * **默认值**：无
    * **其它值**：无

  * **`int $port`**
    * **功能**：监听的端口【在`TCP`模式下需要指定】
    * **默认值**：`0`
    * **其它值**：无

  * **`int $backlog`**
    * **功能**：监听的队列长度
    * **默认值**：`2048`
    * **其它值**：无

* **返回值**

  * 成功监听返回`true`
  * 监听失败返回`false`，可调用`swoole_errno`获取错误码。监听失败后，调用`start`时会立即返回`false`

* **通信协议**

    向监听端口发送数据时，客户端必须在请求前增加4字节、网络字节序的长度值。协议格式为：

```
packet = htonl(strlen(data)) + data;
```

* **使用示例**

```php
$pool->listen('127.0.0.1', 8089);
$pool->listen('unix:/tmp/php.sock');
```

### write()

向对端写入数据，必须在`$ipc_mode`为`SWOOLE_IPC_SOCKET`时才能使用。

```php
Swoole\Process\Pool->write(string $data): bool
```

!> 此方法为内存操作，没有`IO`消耗，发送数据操作是同步阻塞`IO`

* **参数** 

  * **`string $data`**
    * **功能**：写入的数据内容【可多次调用`write`，底层会在`onMessage`函数退出后将数据全部写入`socket`中，并`close`连接】
    * **默认值**：无
    * **其它值**：无

* **使用示例**

  * **服务端**

    ```php
    $pool = new Swoole\Process\Pool(2, SWOOLE_IPC_SOCKET);
    
    $pool->on("Message", function ($pool, $message) {
        echo "Message: {$message}\n";
        $pool->write("hello ");
        $pool->write("world ");
        $pool->write("\n");
    });
    
    $pool->listen('127.0.0.1', 8089);
    $pool->start();
    ```

  * **调用端**

    ```php
    $fp = stream_socket_client("tcp://127.0.0.1:8089", $errno, $errstr) or die("error: $errstr\n");
    $msg = json_encode(['data' => 'hello', 'uid' => 1991]);
    fwrite($fp, pack('N', strlen($msg)) . $msg);
    sleep(1);
    //将显示 hello world\n
    $data = fread($fp, 8192);
    var_dump(substr($data, 4, unpack('N', substr($data, 0, 4))[1]));
    fclose($fp);
    ```

### start()

启动工作进程。

```php
Swoole\Process\Pool->start(): bool
```

!> 启动成功，当前进程进入`wait`状态，管理工作进程；  
启动失败，返回`false`，可使用`swoole_errno`获取错误码。

* **使用示例**

```php
$workerNum = 10;
$pool = new Swoole\Process\Pool($workerNum);

$pool->on("WorkerStart", function ($pool, $workerId) {
    echo "Worker#{$workerId} is started\n";
    $redis = new Redis();
    $redis->pconnect('127.0.0.1', 6379);
    $key = "key1";
    while (true) {
         $msg = $redis->brpop($key, 2);
         if ( $msg == null) continue;
         var_dump($msg);
     }
});

$pool->on("WorkerStop", function ($pool, $workerId) {
    echo "Worker#{$workerId} is stopped\n";
});

$pool->start();
```

* **进程管理**

  * 某个工作进程遇到致命错误、主动退出时管理器会进行回收，避免出现僵尸进程
  * 工作进程退出后，管理器会自动拉起、创建一个新的工作进程
  * 主进程收到`SIGTERM`信号时将停止`fork`新进程，并`kill`所有正在运行的工作进程
  * 主进程收到`SIGUSR1`信号时将将逐个`kill`正在运行的工作进程，并重新启动新的工作进程

* **信号处理**

  底层仅设置了主进程（管理进程）的信号处理，并未对`Worker`工作进程设置信号，需要开发者自行实现信号的监听。

  - 工作进程为异步模式，请使用 [Swoole\Process::signal](/process/process?id=signal) 监听信号
  - 工作进程为同步模式，请使用`pcntl_signal`和`pcntl_signal_dispatch`监听信号

  在工作进程中应当监听`SIGTERM`信号，当主进程需要终止该进程时，会向此进程发送`SIGTERM`信号。如果工作进程未监听`SIGTERM`信号，底层会强行终止当前进程，造成部分逻辑丢失。

```php
$pool->on("WorkerStart", function ($pool, $workerId) {
    $running = true;
    pcntl_signal(SIGTERM, function () use (&$running) {
        $running = false;
    });
    echo "Worker#{$workerId} is started\n";
    $redis = new Redis();
    $redis->pconnect('127.0.0.1', 6379);
    $key = "key1";
    while ($running) {
         $msg = $redis->brpop($key);
         pcntl_signal_dispatch();
         if ( $msg == null) continue;
         var_dump($msg);
     }
});
```

### shutdown()

终止工作进程。

```php
Swoole\Process\Pool->shutdown(): bool
```

### getProcess()

获取当前工作进程对象。返回[Swoole\Process](/process/process)对象。

!> Swoole 版本 >= `v4.2.0` 可用

```php
Swoole\Process\Pool->getProcess(int $worker_id): Swoole\Process
```

* **参数** 

  * **`int $worker_id`**
    * **功能**：指定获取 `worker` 【可选参数,  默认当前 `worker`】
    * **默认值**：无
    * **其它值**：无

!> 必须在`start`之后，在工作进程的`onWorkerStart`或其他回调函数中调用；  
返回的`Process`对象是单例模式，在工作进程中重复调用`getProcess()`将返回同一个对象。

* **使用示例**

```php
$pool = new Swoole\Process\Pool(3);

$pool->on('WorkerStart', function ($pool, $workerId) {
    $process = $pool->getProcess();
    $process->exec('/usr/local/bin/php', ['-r', 'var_dump(swoole_version());']);
});

$pool->start();
```

### detach()

将进程池内当前 Worker 进程脱离管理，底层会立即创建新的进程，老的进程不再处理数据，由应用层代码自行管理生命周期。

!> Swoole 版本 >= `v4.7.0` 可用

```php
Swoole\Process\Pool->detach(): bool
```
