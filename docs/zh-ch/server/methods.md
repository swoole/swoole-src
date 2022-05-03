# 方法

## __construct() 

创建一个[异步IO](/learn?id=同步io异步io)的Server对象。

```php
Swoole\Server::__construct(string $host = '0.0.0.0', int $port = 0, int $mode = SWOOLE_PROCESS, int $sockType = SWOOLE_SOCK_TCP): \Swoole\Server
```

  * **参数**

    * `string $host`

      * 功能：指定监听的ip地址
      * 默认值：无
      * 其它值：无

      !> IPv4使用 `127.0.0.1`表示监听本机，`0.0.0.0`表示监听所有地址  
      IPv6使用`::1`表示监听本机，`::` (相当于`0:0:0:0:0:0:0:0`) 表示监听所有地址

    * `int $port`

      * 功能：指定监听的端口，如`9501`
      * 默认值：无
      * 其它值：无

      !> 如果 `$sockType` 值为 [UnixSocket Stream/Dgram](/learn?id=什么是IPC)，此参数将被忽略  
      监听小于`1024`端口需要`root`权限  
      如果此端口被占用 `server->start` 时会失败

    * `int $mode`

      * 功能：指定运行模式
      * 默认值：[SWOOLE_PROCESS](/learn?id=swoole_process) 多进程模式（默认）
      * 其它值：[SWOOLE_BASE](/learn?id=swoole_base) 基本模式

    * `int $sockType`

      * 功能：指定这组Server的类型
      * 默认值：无
      * 其它值：
        * `SWOOLE_TCP/SWOOLE_SOCK_TCP` tcp ipv4 socket
        * `SWOOLE_TCP6/SWOOLE_SOCK_TCP6` tcp ipv6 socket
        * `SWOOLE_UDP/SWOOLE_SOCK_UDP` udp ipv4 socket
        * `SWOOLE_UDP6/SWOOLE_SOCK_UDP6` udp ipv6 socket
        * [SWOOLE_UNIX_DGRAM](https://github.com/swoole/swoole-src/blob/master/examples/unixsock/dgram_server.php) unix socket dgram
        * [SWOOLE_UNIX_STREAM](https://github.com/swoole/swoole-src/blob/master/examples/unixsock/stream_server.php) unix socket stream 

      !> 使用 `$sock_type` | `SWOOLE_SSL` 可以启用 `SSL` 隧道加密。启用 `SSL` 后必须配置 [ssl_key_file](/server/setting?id=ssl_cert_file) 和 [ssl_cert_file](/server/setting?id=ssl_cert_file)

  * **示例**

```php
$server = new \Swoole\Server($host, $port = 0, $mode = SWOOLE_PROCESS, $sockType = SWOOLE_SOCK_TCP);

// 可以混合使用UDP/TCP，同时监听内网和外网端口，多端口监听参考 addlistener 小节。
$server->addlistener("127.0.0.1", 9502, SWOOLE_SOCK_TCP); // 添加 TCP
$server->addlistener("192.168.1.100", 9503, SWOOLE_SOCK_TCP); // 添加 Web Socket
$server->addlistener("0.0.0.0", 9504, SWOOLE_SOCK_UDP); // UDP
$server->addlistener("/var/run/myserv.sock", 0, SWOOLE_UNIX_STREAM); //UnixSocket Stream
$server->addlistener("127.0.0.1", 9502, SWOOLE_SOCK_TCP | SWOOLE_SSL); //TCP + SSL

$port = $server->addListener("0.0.0.0", 0, SWOOLE_SOCK_TCP); // 系统随机分配端口，返回值为随机分配的端口
echo $port->port;
```
  
## set()

用于设置运行时的各项参数。服务器启动后通过`$serv->setting`来访问`Server->set`方法设置的参数数组。

```php
Swoole\Server->set(array $setting): void
```

!> `Server->set` 必须在 `Server->start` 前调用，具体每个配置的意义请参考[此节](/server/setting)

  * **示例**

```php
$server->set(array(
    'reactor_num'   => 2,     // reactor thread num
    'worker_num'    => 4,     // worker process num
    'backlog'       => 128,   // listen backlog
    'max_request'   => 50,
    'dispatch_mode' => 1,
));
```

## on()

注册`Server`的事件回调函数。

```php
Swoole\Server->on(string $event, mixed $callback): void
```

!> 重复调用`on`方法时会覆盖上一次的设定

  * **参数**

    * `string $event`

      * 功能：回调事件名称
      * 默认值：无
      * 其它值：无

      !> 大小写不敏感，具体有哪些事件回调参考[此节](/server/events)，事件名称字符串不要加`on`

    * `mixed $callback`

      * 功能：回调函数
      * 默认值：无
      * 其它值：无

      !> 可以是函数名的字符串，类静态方法，对象方法数组，匿名函数 参考[此节](/learn?id=几种设置回调函数的方式)。

  * **示例**

```php
$server = new Swoole\Server("127.0.0.1", 9501);
$server->on('connect', function ($server, $fd){
    echo "Client:Connect.\n";
});
$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $server->send($fd, 'Swoole: '.$data);
    $server->close($fd);
});
$server->on('close', function ($server, $fd) {
    echo "Client: Close.\n";
});
$server->start();
```

## addListener()

增加监听的端口。业务代码中可以通过调用 [Server->getClientInfo](/server/methods?id=getclientinfo) 来获取某个连接来自于哪个端口。

```php
Swoole\Server->addListener(string $host, int $port, int $sockType): bool|Swoole\Server\Port
```

!> 监听`1024`以下的端口需要`root`权限  
主服务器是`WebSocket`或`HTTP`协议，新监听的`TCP`端口默认会继承主`Server`的协议设置。必须单独调用`set`方法设置新的协议才会启用新协议 [查看详细说明 ](/server/port)

  * **参数**

    * `string $host`

      * 功能：与 `__construct()` 的 `$host` 相同
      * 默认值：与 `__construct()` 的 `$host` 相同
      * 其它值：与 `__construct()` 的 `$host` 相同

    * `int $port`

      * 功能：与 `__construct()` 的 `$port` 相同
      * 默认值：与 `__construct()` 的 `$port` 相同
      * 其它值：与 `__construct()` 的 `$port` 相同

    * `int $sockType`

      * 功能：与 `__construct()` 的 `$sockType` 相同
      * 默认值：与 `__construct()` 的 `$sockType` 相同
      * 其它值：与 `__construct()` 的 `$sockType` 相同

!> -`Unix Socket`模式下$host参数必须填写可访问的文件路径，`$port`参数忽略  
-`Unix Socket`模式下，客户端`$fd`将不再是数字，而是一个文件路径的字符串  
-`Linux`系统下监听`IPv6`端口后使用`IPv4`地址也可以进行连接

## listen()

此方法是 `addlistener` 的别名。

```php
Swoole\Server->listen(string $host, int $port, int $type): bool|Swoole\Server\Port
```

## addProcess()

添加一个用户自定义的工作进程。此函数通常用于创建一个特殊的工作进程，用于监控、上报或者其他特殊的任务。

```php
Swoole\Server->addProcess(Swoole\Process $process): int
```

!> 不需要执行`start`。在`Server`启动时会自动创建进程，并执行指定的子进程函数

  * **参数**
  
    * [Swoole\Process](/process/process)

      * 功能：`Swoole\Process` 对象
      * 默认值：无
      * 其它值：无

  * **注意**

    !> -创建的子进程可以调用`$server`对象提供的各个方法，如`getClientList/getClientInfo/stats`  
    -在`Worker/Task`进程中可以调用`$process`提供的方法与子进程进行通信  
    -在用户自定义进程中可以调用`$server->sendMessage`与`Worker/Task`进程通信  
    -用户进程内不能使用`Server->task/taskwait`接口  
    -用户进程内可以使用`Server->send/close`等接口  
    -用户进程内应当进行`while(true)`(如下边的示例)或[EventLoop](/learn?id=什么是eventloop)循环(例如创建个定时器)，否则用户进程会不停地退出重启

  * **生命周期**

    ?> -用户进程的生存周期与`Master`和 [Manager](/learn?id=manager进程) 是相同的，不会受到 [reload](/server/methods?id=reload) 影响  
    -用户进程不受`reload`指令控制，`reload`时不会向用户进程发送任何信息  
    -在`shutdown`关闭服务器时，会向用户进程发送`SIGTERM`信号，关闭用户进程  
    -自定义进程会托管到`Manager`进程，如果发生致命错误，`Manager`进程会重新创建一个  
    -自定义进程也不会触发`onWorkerStop`等事件

  * **示例**

    ```php
    $server = new Swoole\Server('127.0.0.1', 9501);
    
    /**
     * 用户进程实现了广播功能，循环接收unixSocket的消息，并发给服务器的所有连接
     */
    $process = new Swoole\Process(function ($process) use ($server) {
        $socket = $process->exportSocket();
        while (true) {
            $msg = $socket->recv();
            foreach ($server->connections as $conn) {
                $server->send($conn, $msg);
            }
        }
    }, false, 2, 1);
    
    $server->addProcess($process);
    
    $server->on('receive', function ($serv, $fd, $reactor_id, $data) use ($process) {
        //群发收到的消息
        $socket = $process->exportSocket();
        $socket->send($data);
    });
    
    $server->start();
    ```

    参考[Process进程间通讯章节](/process/process?id=exportsocket)。

## start()

启动服务器，监听所有`TCP/UDP`端口。

```php
Swoole\Server->start(): bool
```

!> 提示:以下以 [SWOOLE_PROCESS](/learn?id=swoole_process) 模式为例

  * **提示**

    - 启动成功后会创建`worker_num+2`个进程。`Master`进程+`Manager`进程+`serv->worker_num`个`Worker`进程。  
    - 启动失败会立即返回`false`  
    - 启动成功后将进入事件循环，等待客户端连接请求。`start`方法之后的代码不会执行  
    - 服务器关闭后，`start`函数返回`true`，并继续向下执行  
    - 设置了`task_worker_num`会增加相应数量的 [Task进程](/learn?id=taskworker进程)   
    - 方法列表中`start`之前的方法仅可在`start`调用前使用，在`start`之后的方法仅可在`onWorkerStart`、[onReceive](/server/events?id=onreceive)等事件回调函数中使用

  * **扩展**
  
    * Master 主进程

      * 主进程内有多个[Reactor](/learn?id=reactor线程)线程，基于`epoll/kqueue`进行网络事件轮询。收到数据后转发到`Worker`进程去处理
    
    * Manager 进程

      * 对所有`Worker`进程进行管理，`Worker`进程生命周期结束或者发生异常时自动回收，并创建新的`Worker`进程
    
    * Worker 进程

      * 对收到的数据进行处理，包括协议解析和响应请求。未设置`worker_num`，底层会启动与`CPU`数量一致的`Worker`进程。
      * 启动失败扩展内会抛出致命错误，请检查`php error_log`的相关信息。`errno={number}`是标准的`Linux Errno`，可参考相关文档。
      * 如果开启了`log_file`设置，信息会打印到指定的`Log`文件中。

  * **启动失败常见错误**

    * `bind`端口失败,原因是其他进程已占用了此端口
    * 未设置必选回调函数，启动失败
    * `PHP`代码存在致命错误，请检查PHP错误信息`php_errors.log`
    * 执行`ulimit -c unlimited`，打开`core dump`，查看是否有段错误
    * 关闭`daemonize`，关闭`log`，使错误信息可以打印到屏幕

## reload()

安全地重启所有Worker/Task进程。

```php
Swoole\Server->reload(bool $only_reload_taskworker = false): bool
```

!> 例如：一台繁忙的后端服务器随时都在处理请求，如果管理员通过`kill`进程方式来终止/重启服务器程序，可能导致刚好代码执行到一半终止。  
这种情况下会产生数据的不一致。如交易系统中，支付逻辑的下一段是发货，假设在支付逻辑之后进程被终止了。会导致用户支付了货币，但并没有发货，后果非常严重。  
`Swoole`提供了柔性终止/重启的机制，管理员只需要向`Server`发送特定的信号，`Server`的`Worker`进程可以安全的结束。参考 [如何正确的重启服务](/question/use?id=swoole如何正确的重启服务)

  * **参数**
  
    * `bool $only_reload_taskworker`

      * 功能：是否仅重启 [Task进程](/learn?id=taskworker进程)
      * 默认值：false
      * 其它值：无

!> -`reload`有保护机制，当一次`reload`正在进行时，收到新的重启信号会丢弃  
-如果设置了`user/group`，`Worker`进程可能没有权限向`master`进程发送信息，这种情况下必须使用`root`账户，在`shell`中执行`kill`指令进行重启  
-`reload`指令对 [addProcess](/server/methods?id=addProcess) 添加的用户进程无效
       
  * **扩展**
  
    * **发送信号**
    
        * `SIGTERM`: 向主进程/管理进程发送此信号服务器将安全终止
        * 在PHP代码中可以调用`$serv->shutdown()`完成此操作
        * `SIGUSR1`: 向主进程/管理进程发送`SIGUSR1`信号，将平稳地`restart`所有`Worker`进程和`TaskWorker`进程
        * `SIGUSR2`: 向主进程/管理进程发送`SIGUSR2`信号，将平稳地重启所有`Task`进程
        * 在PHP代码中可以调用`$serv->reload()`完成此操作
        
    ```shell
    # 重启所有worker进程
    kill -USR1 主进程PID
    
    # 仅重启task进程
    kill -USR2 主进程PID
    ```
      
      > [参考：Linux信号列表](/other/signal)

    * **Process模式**
    
        在`Process`启动的进程中，来自客户端的`TCP`连接是在`Master`进程内维持的，`worker`进程的重启和异常退出，不会影响连接本身。

    * **Base模式**
    
        在`Base`模式下，客户端连接直接维持在`Worker`进程中，因此`reload`时会切断所有连接。

    !> `Base`模式不支持 reload [Task进程](/learn?id=taskworker进程)
    
    * **Reload有效范围**

      `Reload`操作只能重新载入`Worker`进程启动后加载的PHP文件，使用`get_included_files`函数来列出哪些文件是在`WorkerStart`之前就加载的PHP文件，在此列表中的PHP文件，即使进行了`reload`操作也无法重新载入。要关闭服务器重新启动才能生效。

    ```php
    $serv->on('WorkerStart', function(Swoole\Server $server, int $workerId) {
        var_dump(get_included_files()); //此数组中的文件表示进程启动前就加载了，所以无法reload
    });
    ```

    * **APC/OPcache**
    
        如果`PHP`开启了`APC/OPcache`，`reload`重载入时会受到影响，有`2`种解决方案
        
        * 打开`APC/OPcache`的`stat`检测，如果发现文件更新`APC/OPcache`会自动更新`OPCode`
        * 在`onWorkerStart`中加载文件（require、include等函数）之前执行`apc_clear_cache`或`opcache_reset`刷新`OPCode`缓存

  * **注意**

  !> -平滑重启只对`onWorkerStart`或[onReceive](/server/events?id=onreceive)等在`Worker`进程中`include/require`的PHP文件有效  
-`Server`启动前就已经`include/require`的PHP文件，不能通过平滑重启重新加载  
-对于`Server`的配置即`$serv->set()`中传入的参数设置，必须关闭/重启整个`Server`才可以重新加载  
-`Server`可以监听一个内网端口，然后可以接收远程的控制命令，去重启所有`Worker`进程

## stop()

使当前`Worker`进程停止运行，并立即触发`onWorkerStop`回调函数。

```php
Swoole\Server->stop(int $workerId = -1, bool $waitEvent = false): bool
```

  * **参数**

    * `int $workerId`

      * 功能：指定 `worker id`
      * 默认值：-1
      * 其它值：无

    * `bool $waitEvent`

      * 功能：控制退出策略，`false`表示立即退出，`true`表示等待事件循环为空时再退出
      * 默认值：false
      * 其它值：true

  * **提示**

    !> -[异步IO](/learn?id=同步io异步io)服务器在调用`stop`退出进程时，可能仍然有事件在等待。比如使用了`Swoole\MySQL->query`，发送了`SQL`语句，但还在等待`MySQL`服务器返回结果。这时如果进程强制退出，`SQL`的执行结果就会丢失了。  
    -设置`$waitEvent = true`后，底层会使用[异步安全重启](/question/use?id=swoole如何正确的重启服务)策略。先通知`Manager`进程，重新启动一个新的`Worker`来处理新的请求。当前旧的`Worker`会等待事件，直到事件循环为空或者超过`max_wait_time`后，退出进程，最大限度的保证异步事件的安全性。

## shutdown()

关闭服务。

```php
Swoole\Server->shutdown(): void
```

  * **提示**

    * 此函数可以用在`Worker`进程内
    * 向主进程发送`SIGTERM`也可以实现关闭服务

```shell
kill -15 主进程PID
```

## tick()

添加`tick`定时器，可以自定义回调函数。此函数是 [Swoole\Timer::tick](/timer?id=tick) 的别名。

```php
Swoole\Server->tick(int $millisecond, mixed $callback): void
```

  * **参数**

    * `int $millisecond`

      * 功能：间隔时间【毫秒】
      * 默认值：无
      * 其它值：无

    * `mixed $callback`

      * 功能：回调函数
      * 默认值：无
      * 其它值：无

  * **注意**

  !> -`Worker`进程结束运行后，所有定时器都会自动销毁  
-`tick/after`定时器不能在`Server->start`之前使用

  * **示例**

    * 在 [onReceive](/server/events?id=onreceive) 中使用

    ```php
    function onReceive(Swoole\Server $server, int $fd, int $reactorId, mixed $data)
    {
        $server->tick(1000, function () use ($server, $fd) {
            $server->send($fd, "hello world");
        });
    }
    ```

    * 在 `onWorkerStart` 中使用

    ```php
    function onWorkerStart(Swoole\Server $server, int $workerId)
    {
        if (!$server->taskworker) {
            $server->tick(1000, function ($id) {
              var_dump($id);
            });
        } else {
            //task
            $server->tick(1000);
        }
    }
    ```

## after()

添加一个一次性定时器，执行完成后就会销毁。此函数是 [Swoole\Timer::after](/timer?id=after) 的别名。

```php
Swoole\Server->after(int $millisecond, mixed $callback)
```

  * **参数**

    * `int $millisecond`

      * 功能：执行时间【毫秒】
      * 默认值：无
      * 其它值：无
      * 版本影响：在 `Swoole v4.2.10` 以下版本最大不得超过 `86400000`

    * `mixed $callback`

      * 功能：回调函数，必须是可以调用的，`callback` 函数不接受任何参数
      * 默认值：无
      * 其它值：无

  * **注意**

  !> -定时器的生命周期是进程级的，当使用`reload`或`kill`重启关闭进程时，定时器会全部被销毁  
-如果有某些定时器存在关键逻辑和数据，请在`onWorkerStop`回调函数中实现，或参考 [如何正确的重启服务](/question/use?id=swoole如何正确的重启服务)

## defer()

延后执行一个函数，是 [Event::defer](/event?id=defer) 的别名。

```php
Swoole\Server->defer(callable $callback): void
```

  * **参数**

    * `callable $callback`

      * 功能：回调函数【必填】，可以是可执行的函数变量，可以是字符串、数组、匿名函数
      * 默认值：无
      * 其它值：无

  * **注意**

  !> -底层会在[EventLoop](/learn?id=什么是eventloop)循环完成后执行此函数。此函数的目的是为了让一些PHP代码延后执行，程序优先处理其他的`IO`事件。比如某个回调函数有CPU密集计算又不是很着急，可以让进程处理完其他的事件再去CPU密集计算  
-底层不保证`defer`的函数会立即执行，如果是系统关键逻辑，需要尽快执行，请使用`after`定时器实现  
-在`onWorkerStart`回调中执行`defer`时，必须要等到有事件发生才会回调

  * **示例**

```php
function query($server, $db) {
    $server->defer(function() use ($db) {
        $db->close();
    });
}
```

## clearTimer()

清除`tick/after`定时器，此函数是 [Swoole\Timer::clear](/timer?id=clear) 的别名。

```php
Swoole\Server->clearTimer(int $timerId): bool
```

  * **参数**

    * `int $timerId`

      * 功能：指定定时器id
      * 默认值：无
      * 其它值：无

  * **注意**

  !> `clearTimer`仅可用于清除当前进程的定时器

  * **示例**

```php
$timerId = $server->tick(1000, function ($id) use ($server) {
    $server->clearTimer($id);//$id是定时器的id
});
```

## close()

关闭客户端连接。

```php
Swoole\Server->close(int $fd, bool $reset = false): bool
```

  * **参数**

    * `int $fd`

      * 功能：指定关闭的 `fd` (文件描述符)
      * 默认值：无
      * 其它值：无

    * `bool $reset`

      * 功能：设置为`true`会强制关闭连接，丢弃发送队列中的数据
      * 默认值：false
      * 其它值：true

  * **注意**

  !> -`Server`主动`close`连接，也一样会触发[onClose](/server/events?id=onclose)事件  
-不要在`close`之后写清理逻辑。应当放置到[onClose](/server/events?id=onclose)回调中处理  
-`HTTP\Server`的`fd`在上层回调方法的`response`中获取

  * **示例**

```php
$server->on('request', function ($request, $response) use ($server) {
    $server->close($response->fd);
});
```

## send()

向客户端发送数据。

```php
Swoole\Server->send(int $fd, string $data, int $serverSocket  = -1): bool
```

  * **参数**

    * `int $fd`

      * 功能：指定客户端的文件描述符
      * 默认值：无
      * 其它值：无

    * `string $data`

      * 功能：发送的数据，`TCP`协议最大不得超过`2M`，可修改 [buffer_output_size](/server/setting?id=buffer_output_size) 改变允许发送的最大包长度
      * 默认值：无
      * 其它值：无

    * `int $serverSocket`

      * 功能：向[UnixSocket DGRAM](https://github.com/swoole/swoole-src/blob/master/examples/unixsock/dgram_server.php)对端发送数据时需要此项参数，TCP客户端不需要填写
      * 默认值：-1
      * 其它值：无

  * **提示**

    !> 发送过程是异步的，底层会自动监听可写，将数据逐步发送给客户端，也就是说不是`send`返回后对端就收到数据了。

    * 安全性
      * `send`操作具有原子性，多个进程同时调用`send`向同一个`TCP`连接发送数据，不会发生数据混杂

    * 长度限制
      * 如果要发送超过`2M`的数据，可以将数据写入临时文件，然后通过`sendfile`接口进行发送
      * 通过设置 [buffer_output_size](/server/setting?id=buffer_output_size) 参数可以修改发送长度的限制
      * 在发送超过`8K`的数据时，底层会启用`Worker`进程的共享内存，需要进行一次`Mutex->lock`操作

    * 缓存区
      * 当`Worker`进程的[unixSocket](/learn?id=什么是IPC)缓存区已满时，发送`8K`数据将启用临时文件存储
      * 如果连续向同一个客户端发送大量数据，客户端来不及接收会导致`Socket`内存缓存区塞满，Swoole底层会立即返回`false`,`false`时可以将数据保存到磁盘，等待客户端收完已发送的数据后再进行发送

    * [协程调度](/coroutine?id=协程调度)
      * 在协程模式开启了[send_yield](/server/setting?id=send_yield)情况下`send`遇到缓存区已满时会自动挂起，当数据被对端读走一部分后恢复协程，继续发送数据。

    * [UnixSocket](/learn?id=什么是IPC)
      * 监听[UnixSocket DGRAM](https://github.com/swoole/swoole-src/blob/master/examples/unixsock/dgram_server.php)端口时，可以使用`send`向对端发送数据。

      ```php
      $server->on("packet", function (Swoole\Server $server, $data, $addr){
          $server->send($addr['address'], 'SUCCESS', $addr['server_socket']);
      });
      ```

## sendfile()

发送文件到`TCP`客户端连接。

```php
Swoole\Server->sendfile(int $fd, string $filename, int $offset = 0, int $length = 0): bool
```

  * **参数**

    * `int $fd`

      * 功能：指定客户端的文件描述符
      * 默认值：无
      * 其它值：无

    * `string $filename`

      * 功能：要发送的文件路径，如果文件不存在会返回`false`
      * 默认值：无
      * 其它值：无

    * `int $offset`

      * 功能：指定文件偏移量，可以从文件的某个位置起发送数据
      * 默认值：0 【默认为`0`，表示从文件头部开始发送】
      * 其它值：无

    * `int $length`

      * 功能：指定发送的长度
      * 默认值：文件尺寸
      * 其它值：无

  * **注意**

  !> 此函数与`Server->send`都是向客户端发送数据，不同的是`sendfile`的数据来自于指定的文件

## sendto()

向任意的客户端`IP:PORT`发送`UDP`数据包。

```php
Swoole\Server->sendto(string $ip, int $port, string $data, int $serverSocket = -1): bool
```

  * **参数**

    * `string $ip`

      * 功能：指定客户端 `ip`
      * 默认值：无
      * 其它值：无

      ?> `$ip`为`IPv4`或`IPv6`字符串，如`192.168.1.102`。如果`IP`不合法会返回错误

    * `int $port`

      * 功能：指定客户端 `port`
      * 默认值：无
      * 其它值：无

      ?> `$port`为 `1-65535`的网络端口号，如果端口错误发送会失败

    * `string $data`

      * 功能：要发送的数据内容，可以是文本或者二进制内容
      * 默认值：无
      * 其它值：无

    * `int $serverSocket`

      * 功能：指定使用哪个端口发送数据包的对应端口`server_socket`描述符【可以在[onPacket事件](/server/events?id=onpacket)的`$clientInfo`中获取】
      * 默认值：无
      * 其它值：无

      ?> 服务器可能会同时监听多个`UDP`端口，参考[多端口监听](/server/port)，此参数可以指定使用哪个端口发送数据包

  * **注意**

  !> 必须监听了`UDP`的端口，才可以使用向`IPv4`地址发送数据  
  必须监听了`UDP6`的端口，才可以使用向`IPv6`地址发送数据

  * **示例**

```php
//向IP地址为220.181.57.216主机的9502端口发送一个hello world字符串。
$server->sendto('220.181.57.216', 9502, "hello world");
//向IPv6服务器发送UDP数据包
$server->sendto('2600:3c00::f03c:91ff:fe73:e98f', 9501, "hello world");
```

## sendwait()

同步地向客户端发送数据。

```php
Swoole\Server->sendwait(int $fd, string $data): bool
```

  * **参数**

    * `int $fd`

      * 功能：指定客户端的文件描述符
      * 默认值：无
      * 其它值：无

    * `string $data`

      * 功能：指定客户端的文件描述符
      * 默认值：无
      * 其它值：无

  * **提示**

    * 有一些特殊的场景，`Server`需要连续向客户端发送数据，而`Server->send`数据发送接口是纯异步的，大量数据发送会导致内存发送队列塞满。

    * 使用`Server->sendwait`就可以解决此问题，`Server->sendwait`会等待连接可写。直到数据发送完毕才会返回。

  * **注意**

  !> `sendwait`目前仅可用于[SWOOLE_BASE](/learn?id=swoole_base)模式  
  `sendwait`只用于本机或内网通信，外网连接请勿使用`sendwait`，在`enable_coroutine`=>true(默认开启)的时候也不要用这个函数，会卡死其他协程，只有同步阻塞的服务器才可以用。

## sendMessage()

向任意`Worker`进程或者 [Task进程](/learn?id=taskworker进程)发送消息。在非主进程和管理进程中可调用。收到消息的进程会触发`onPipeMessage`事件。

```php
Swoole\Server->sendMessage(string $message, int $workerId): bool
```

  * **参数**

    * `string $message`

      * 功能：为发送的消息数据内容，没有长度限制，但超过`8K`时会启动内存临时文件
      * 默认值：无
      * 其它值：无

    * `int $workerId`

      * 功能：目标进程的`ID`，范围参考[$worker_id](/server/properties?id=worker_id)
      * 默认值：无
      * 其它值：无

  * **提示**

    * 在`Worker`进程内调用`sendMessage`是[异步IO](/learn?id=同步io异步io)的，消息会先存到缓冲区，可写时向[unixSocket](/learn?id=什么是IPC)发送此消息
    * 在 [Task进程](/learn?id=taskworker进程) 内调用`sendMessage`默认是[同步IO](/learn?id=同步io异步io)，但有些情况会自动转换成异步IO，参考[同步IO转换成异步IO](/learn?id=同步io转换成异步io)
    * 在 [User进程](/server/methods?id=addprocess) 内调用`sendMessage`和Task一样，默认同步阻塞的，参考[同步IO转换成异步IO](/learn?id=同步io转换成异步io)

  * **注意**

  !> - 如果`sendMessage()`是[异步IO](/learn?id=同步io转换成异步io)的，如果对端进程因为种种原因不接收数据，千万不要一直调用`sendMessage()`，会导致占用大量的内存资源。可以增加一个应答机制，如果对端不回应就暂停调用；  
-`MacOS/FreeBSD下`超过`2K`就会使用临时文件存储；  
-使用[sendMessage](/server/methods?id=sendMessage)必须注册`onPipeMessage`事件回调函数；  
-设置了 [task_ipc_mode](/server/setting?id=task_ipc_mode) = 3 将无法使用[sendMessage](/server/methods?id=sendMessage)向特定的task进程发送消息。

  * **示例**

```php
$server = new Swoole\Server('0.0.0.0', 9501);

$server->set(array(
    'worker_num'      => 2,
    'task_worker_num' => 2,
));
$server->on('pipeMessage', function ($server, $src_worker_id, $data) {
    echo "#{$server->worker_id} message from #$src_worker_id: $data\n";
});
$server->on('task', function ($server, $task_id, $src_worker_id, $data) {
    var_dump($task_id, $src_worker_id, $data);
});
$server->on('finish', function ($server, $task_id, $data) {

});
$server->on('receive', function (Swoole\Server $server, $fd, $reactor_id, $data) {
    if (trim($data) == 'task') {
        $server->task("async task coming");
    } else {
        $worker_id = 1 - $server->worker_id;
        $server->sendMessage("hello task process", $worker_id);
    }
});

$server->start();
```

## exist()

检测`fd`对应的连接是否存在。

```php
Swoole\Server->exist(int $fd): bool
```

  * **参数**

    * `int $fd`

      * 功能：文件描述符
      * 默认值：无
      * 其它值：无

  * **提示**
  
    * 此接口是基于共享内存计算，没有任何`IO`操作

## pause()

停止接收数据。

```php
Swoole\Server->pause(int $fd)
```

  * **参数**

    * `int $fd`

      * 功能：指定文件描述符
      * 默认值：无
      * 其它值：无

  * **提示**

    * 调用此函数后会将连接从[EventLoop](/learn?id=什么是eventloop)中移除，不再接收客户端数据。
    * 此函数不影响发送队列的处理
    * 只能在`SWOOLE_PROCESS`模式下，调用`pause`后，可能有部分数据已经到达`Worker`进程，因此仍然可能会触发[onReceive](/server/events?id=onreceive)事件

## resume()

恢复数据接收。与`pause`方法成对使用。

```php
Swoole\Server->resume(int $fd)
```

  * **参数**

    * `int $fd`

      * 功能：指定文件描述符
      * 默认值：无
      * 其它值：无

  * **提示**

    * 调用此函数后会将连接重新加入到[EventLoop](/learn?id=什么是eventloop)中，继续接收客户端数据

## getCallback()

获取 Server 指定名称的回调函数

```php
Swoole\Server->getCallback(string $event_name)
```

  * **参数**

    * `string $event_name`

      * 功能：事件名称，不需要加`on`，不区分大小写
      * 默认值：无
      * 其它值：参考 [事件](/server/events)

  * **返回值**

    * 对应回调函数存在时，根据不同的[回调函数设置方式](/learn?id=四种设置回调函数的方式)返回 `Closure` / `string` / `array`
    * 对应回调函数不存在时，返回`null`

## getClientInfo()

获取连接的信息，别名是`Swoole\Server->connection_info()`

```php
Swoole\Server->getClientInfo(int $fd, int $reactorId, bool $ignoreError = false): bool|array
```

  * **参数**

    * `int $fd`

      * 功能：指定文件描述符
      * 默认值：无
      * 其它值：无

    * `int $reactorId`

      * 功能：连接所在的[Reactor](/learn?id=reactor线程)线程`ID`
      * 默认值：无
      * 其它值：无

    * `bool $ignoreError`

      * 功能：是否忽略错误，如果设置为`true`，即使连接关闭也会返回连接的信息
      * 默认值：无
      * 其它值：无

  * **提示**

    * 客户端证书

      * 仅在[onConnect](/server/events?id=onconnect)触发的进程中才能获取到证书
      * 格式为`x509`格式，可使用`openssl_x509_parse`函数获取到证书信息

    * 当使用 [dispatch_mode](/server/setting?id=dispatch_mode) = 1/3 配置时，考虑到这种数据包分发策略用于无状态服务，当连接断开后相关信息会直接从内存中删除，所以`Server->getClientInfo`是获取不到相关连接信息的。

  * **返回值**

    * 调用失败返回`false`
    * 调用成功返回`array`

```php
$fd_info = $server->getClientInfo($fd);
var_dump($fd_info);

array(7) {
  ["reactor_id"]=>
  int(3)
  ["server_fd"]=>
  int(14)
  ["server_port"]=>
  int(9501)
  ["remote_port"]=>
  int(19889)
  ["remote_ip"]=>
  string(9) "127.0.0.1"
  ["connect_time"]=>
  int(1390212495)
  ["last_time"]=>
  int(1390212760)
}
```

参数 | 作用
---|---
reactor_id | 来自哪个Reactor线程
server_fd | 来自哪个监听端口socket，这里不是客户端连接的fd
server_port | 来自哪个监听端口
remote_port | 客户端连接的端口
remote_ip | 客户端连接的IP地址
connect_time | 客户端连接到Server的时间，单位秒，由master进程设置
last_time | 最后一次收到数据的时间，单位秒，由master进程设置
close_errno | 连接关闭的错误码，如果连接异常关闭，close_errno的值是非零，可以参考Linux错误信息列表
recv_queued_bytes | 等待处理的数据量
send_queued_bytes | 等待发送的数据量
websocket_status | [可选项] WebSocket连接状态，当服务器是Swoole\WebSocket\Server时会额外增加此项信息
uid | [可选项] 使用bind绑定了用户ID时会额外增加此项信息
ssl_client_cert | [可选项] 使用SSL隧道加密，并且客户端设置了证书时会额外添加此项信息

## getClientList()

遍历当前`Server`所有的客户端连接，`Server::getClientList`方法是基于共享内存的，不存在`IOWait`，遍历的速度很快。另外`getClientList`会返回所有`TCP`连接，而不仅仅是当前`Worker`进程的`TCP`连接。别名是`Swoole\Server->connection_list()`

```php
Swoole\Server->getClientList(int $start_fd = 0, int $pageSize = 10): bool|array
```

  * **参数**

    * `int $start_fd`

      * 功能：指定起始`fd`
      * 默认值：无
      * 其它值：无

    * `int $pageSize`

      * 功能：每页取多少条，最大不得超过`100`
      * 默认值：无
      * 其它值：无

  * **返回值**

    * 调用成功将返回一个数字索引数组，元素是取到的`$fd`。数组会按从小到大排序。最后一个`$fd`作为新的`start_fd`再次尝试获取
    * 调用失败返回`false`

  * **提示**

    * 推荐使用 [Server::$connections](/server/properties?id=connections) 迭代器来遍历连接
    * `getClientList`仅可用于`TCP`客户端，`UDP`服务器需要自行保存客户端信息
    * [SWOOLE_BASE](/learn?id=swoole_base)模式下只能获取当前进程的连接

  * **示例**
  
```php
$start_fd = 0;
while (true) {
  $conn_list = $server->getClientList($start_fd, 10);
  if ($conn_list === false or count($conn_list) === 0) {
      echo "finish\n";
      break;
  }
  $start_fd = end($conn_list);
  var_dump($conn_list);
  foreach ($conn_list as $fd) {
      $server->send($fd, "broadcast");
  }
}
```

## bind()

将连接绑定一个用户定义的`UID`，可以设置[dispatch_mode](/server/setting?id=dispatch_mode)=5设置以此值进行`hash`固定分配。可以保证某一个`UID`的连接全部会分配到同一个`Worker`进程。

```php
Swoole\Server->bind(int $fd, int $uid): bool
```

  * **参数**

    * `int $fd`

      * 功能：指定连接的 `fd`
      * 默认值：无
      * 其它值：无

    * `int $uid`

      * 功能：要绑定的`UID`，必须为非`0`的数字
      * 默认值：无
      * 其它值：`UID`最大不能超过`4294967295`，最小不能小于`-2147483648`

  * **提示**

    * 可以使用`$serv->getClientInfo($fd)` 查看连接所绑定`UID`的值
    * 在默认的[dispatch_mode](/server/setting?id=dispatch_mode)=2设置下，`Server`会按照`socket fd`来分配连接数据到不同的`Worker`进程。因为`fd`是不稳定的，一个客户端断开后重新连接，`fd`会发生改变。这样这个客户端的数据就会被分配到别的`Worker`。使用`bind`之后就可以按照用户定义的`UID`进行分配。即使断线重连，相同`UID`的`TCP`连接数据会被分配相同的`Worker`进程。

    * 时序问题

      * 客户端连接服务器后，连续发送多个包，可能会存在时序问题。在`bind`操作时，后续的包可能已经`dispatch`，这些数据包仍然会按照`fd`取模分配到当前进程。只有在`bind`之后新收到的数据包才会按照`UID`取模分配。
      * 因此如果要使用`bind`机制，网络通信协议需要设计握手步骤。客户端连接成功后，先发一个握手请求，之后客户端不要发任何包。在服务器`bind`完后，并回应之后。客户端再发送新的请求。

    * 重新绑定

      * 某些情况下，业务逻辑需要用户连接重新绑定`UID`。这时可以切断连接，重新建立`TCP`连接并握手，绑定到新的`UID`。

    * 绑定负数`UID`

      * 如果绑定的`UID`为负数，会被底层转换为`32位无符号整数`，PHP层需要转为`32位有符号整数`，可使用：
      
  ```php
  $uid = -10;
  $server->bind($fd, $uid);
  $bindUid = $server->connection_info($fd)['uid'];
  $bindUid = $bindUid >> 31 ? (~($bindUid - 1) & 0xFFFFFFFF) * -1 : $bindUid;
  var_dump($bindUid === $uid);
  ```

  * **注意**

!> -仅在设置`dispatch_mode=5`时有效  
-未绑定`UID`时默认使用`fd`取模进行分配  
-同一个连接只能被`bind`一次，如果已经绑定了`UID`，再次调用`bind`会返回`false`

  * **示例**

```php
$serv = new Swoole\Server('0.0.0.0', 9501);

$serv->fdlist = [];

$serv->set([
    'worker_num' => 4,
    'dispatch_mode' => 5,   //uid dispatch
]);

$serv->on('connect', function ($serv, $fd, $reactor_id) {
    echo "{$fd} connect, worker:" . $serv->worker_id . PHP_EOL;
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
    $conn = $serv->connection_info($fd);
    print_r($conn);
    echo "worker_id: " . $serv->worker_id . PHP_EOL;
    if (empty($conn['uid'])) {
        $uid = $fd + 1;
        if ($serv->bind($fd, $uid)) {
            $serv->send($fd, "bind {$uid} success");
        }
    } else {
        if (!isset($serv->fdlist[$fd])) {
            $serv->fdlist[$fd] = $conn['uid'];
        }
        print_r($serv->fdlist);
        foreach ($serv->fdlist as $_fd => $uid) {
            $serv->send($_fd, "{$fd} say:" . $data);
        }
    }
});

$serv->on('close', function ($serv, $fd, $reactor_id) {
    echo "{$fd} Close". PHP_EOL;
    unset($serv->fdlist[$fd]);
});

$serv->start();
```

## stats()

得到当前`Server`的活动`TCP`连接数，启动时间等信息，`accept/close`(建立连接/关闭连接)的总次数等信息。

```php
Swoole\Server->stats(): array
```

  * **示例**

```php
array(14) {
  ["start_time"]=>
  int(1604969791)
  ["connection_num"]=>
  int(1)
  ["accept_count"]=>
  int(1)
  ["close_count"]=>
  int(0)
  ["worker_num"]=>
  int(1)
  ["idle_worker_num"]=>
  int(0)
  ["task_worker_num"]=>
  int(1)
  ["tasking_num"]=>
  int(0)
  ["request_count"]=>
  int(0)
  ["dispatch_count"]=>
  int(1)
  ["worker_request_count"]=>
  int(0)
  ["worker_dispatch_count"]=>
  int(1)
  ["task_idle_worker_num"]=>
  int(1)
  ["coroutine_num"]=>
  int(1)
}
```

参数 | 作用
---|---
start_time | 服务器启动的时间
connection_num | 当前连接的数量
accept_count | 接受了多少个连接
close_count | 关闭的连接数量
worker_num  | 开启了多少个worker进程
idle_worker_num | 空闲的worker进程数
task_worker_num | 开启了多少个task_worker进程【`v4.5.7`可用】
tasking_num | 当前正在排队的任务数
request_count | Server收到的请求次数【只有onReceive、onMessage、onRequset、onPacket四种数据请求计算request_count】
dispatch_count | Server发送到Worker的包数量【`v4.5.7`可用，仅在[SWOOLE_PROCESS](/learn?id=swoole_process)模式下有效】
worker_request_count | 当前Worker进程收到的请求次数【worker_request_count超过max_request时工作进程将退出】
worker_dispatch_count | master进程向当前Worker进程投递任务的计数，在[master进程](/learn?id=reactor线程)进行dispatch时增加计数
task_queue_num | 消息队列中的task数量【用于Task】
task_queue_bytes | 消息队列的内存占用字节数【用于Task】
task_idle_worker_num |空闲的task进程数量
coroutine_num | 当前协程数量【用于Coroutine】，想获取更多信息参考[此节](/coroutine/gdb)

## task()

投递一个异步任务到`task_worker`池中。此函数是非阻塞的，执行完毕会立即返回。`Worker`进程可以继续处理新的请求。使用`Task`功能，必须先设置 `task_worker_num`，并且必须设置`Server`的[onTask](/server/events?id=ontask)和[onFinish](/server/events?id=onfinish)事件回调函数。

```php
Swoole\Server->task(mixed $data, int $dstWorkerId = -1, callable $finishCallback): int
```

  * **参数**

    * `mixed $data`

      * 功能：要投递的任务数据，必须是可序列化的PHP变量
      * 默认值：无
      * 其它值：无

    * `int $dstWorkerId`

      * 功能：可以指定要给投递给哪个 [Task进程](/learn?id=taskworker进程)，传入 Task 进程的`ID`即可，范围为`[0, $server->setting['task_worker_num']-1]`
      * 默认值：-1【默认为`-1`表示随机投递，底层会自动选择一个空闲 [Task进程](/learn?id=taskworker进程)】
      * 其它值：`[0, $server->setting['task_worker_num']-1]`

    * `callable $finishCallback`

      * 功能：`finish` 回调函数，如果任务设置了回调函数，`Task`返回结果时会直接执行指定的回调函数，不再执行`Server`的[onFinish](/server/events?id=onfinish)回调，只有在`Worker`进程中投递任务才可触发
      * 默认值：`null`
      * 其它值：无

  * **返回值**

    * 调用成功，返回值为整数`$task_id`，表示此任务的`ID`。如果有`finish`回调，[onFinish](/server/events?id=onfinish)回调中会携带`$task_id`参数
    * 调用失败，返回值为`false`，`$task_id`可能为`0`，因此必须使用`===`判断是否失败

  * **提示**

    * 此功能用于将慢速的任务异步地去执行，比如一个聊天室服务器，可以用它来进行发送广播。当任务完成时，在[task进程](/learn?id=taskworker进程)中调用`$serv->finish("finish")`告诉`worker`进程此任务已完成。当然`Swoole\Server->finish`是可选的。
    * `task`底层使用[unixSocket](/learn?id=什么是IPC)通信，是全内存的，没有`IO`消耗。单进程读写性能可达`100万/s`，不同的进程使用不同的`unixSocket`通信，可以最大化利用多核。
    * 未指定目标[Task进程](/learn?id=taskworker进程)，调用`task`方法会判断 [Task进程](/learn?id=taskworker进程)的忙闲状态，底层只会向处于空闲状态的[Task进程](/learn?id=taskworker进程)投递任务。如果所有[Task进程](/learn?id=taskworker进程)均处于忙的状态，底层会轮询投递任务到各个进程。可以使用 [server->stats](/server/methods?id=stats) 方法获取当前正在排队的任务数量。
    * 第三个参数，可以直接设置[onFinish](/server/events?id=onfinish)函数，如果任务设置了回调函数，`Task`返回结果时会直接执行指定的回调函数，不再执行`Server`的[onFinish](/server/events?id=onfinish)回调，只有在`Worker`进程中投递任务才可触发

    ```php
    $server->task($data, -1, function (Swoole\Server $server, $task_id, $data) {
        echo "Task Callback: ";
        var_dump($task_id, $data);
    });
    ```

    * `$task_id`是从`0-42`亿的整数，在当前进程内是唯一的
    * 默认不启动`task`功能，需要在手动设置`task_worker_num`来启动此功能
    * `TaskWorker`的数量在[Server->set()](/server/methods?id=set)参数中调整，如`task_worker_num => 64`，表示启动`64`个进程来接收异步任务

  * **配置参数**

    * `Server->task/taskwait/finish` `3`个方法当传入的`$data`数据超过`8K`时会启用临时文件来保存。当临时文件内容超过
    [server->package_max_length](/server/setting?id=package_max_length) 时底层会抛出一个警告。此警告不影响数据的投递，过大的`Task`可能会存在性能问题。
    
    ```shell
    WARN: task package is too big.
    ```

  * **单向任务**

    * 从`Master`、`Manager`、`UserProcess`进程中投递的任务，是单向的，在`TaskWorker`进程中无法使用`return`或`Server->finish()`方法返回结果数据。

  * **注意**

  !> -`task`方法不能在[task进程](/learn?id=taskworker进程)中调用  
-使用`task`必须为`Server`设置[onTask](/server/events?id=ontask)和[onFinish](/server/events?id=onfinish)回调，否则`Server->start`会失败  
-`task`操作的次数必须小于[onTask](/server/events?id=ontask)处理速度，如果投递容量超过处理能力，`task`数据会塞满缓存区，导致`Worker`进程发生阻塞。`Worker`进程将无法接收新的请求  
-使用[addProcess](/server/method?id=addProcess)添加的用户进程中可以使用`task`单向投递任务，但不能返回结果数据。请使用[sendMessage](/server/methods?id=sendMessage)接口与`Worker/Task`进程通信

  * **示例**

```php
$server = new Swoole\Server("127.0.0.1", 9501, SWOOLE_BASE);

$server->set(array(
    'worker_num'      => 2,
    'task_worker_num' => 4,
));

$server->on('Receive', function (Swoole\Server $server, $fd, $reactor_id, $data) {
    echo "接收数据" . $data . "\n";
    $data    = trim($data);
    $server->task($data, -1, function (Swoole\Server $server, $task_id, $data) {
        echo "Task Callback: ";
        var_dump($task_id, $data);
    });
    $task_id = $server->task($data, 0);
    $server->send($fd, "分发任务，任务id为$task_id\n");
});

$server->on('Task', function (Swoole\Server $server, $task_id, $reactor_id, $data) {
    echo "Tasker进程接收到数据";
    echo "#{$server->worker_id}\tonTask: [PID={$server->worker_pid}]: task_id=$task_id, data_len=" . strlen($data) . "." . PHP_EOL;
    $server->finish($data);
});

$server->on('Finish', function (Swoole\Server $server, $task_id, $data) {
    echo "Task#$task_id finished, data_len=" . strlen($data) . PHP_EOL;
});

$server->on('workerStart', function ($server, $worker_id) {
    global $argv;
    if ($worker_id >= $server->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]}: task_worker");
    } else {
        swoole_set_process_name("php {$argv[0]}: worker");
    }
});

$server->start();
```

## taskwait()

`taskwait`与`task`方法作用相同，用于投递一个异步的任务到 [task进程](/learn?id=taskworker进程)池去执行。与`task`不同的是`taskwait`是同步等待的，直到任务完成或者超时返回。`$result`为任务执行的结果，由`$server->finish`函数发出。如果此任务超时，这里会返回`false`。

```php
Swoole\Server->taskwait(mixed $data, float $timeout = 0.5, int $dstWorkerId = -1): string|bool
```

  * **参数**

    * `mixed $data`

      * 功能：投递的任务数据，可以是任意类型，非字符串类型底层会自动进行串化
      * 默认值：无
      * 其它值：无

    * `float $timeout`

      * 功能：超时时间，浮点型，单位为秒，最小支持`1ms`粒度，超过规定时间内 [Task进程](/learn?id=taskworker进程)未返回数据，`taskwait`将返回`false`，不再处理后续的任务结果数据
      * 默认值：无
      * 其它值：无

    * `int $dstWorkerId`

      * 功能：指定要给投递给哪个 [Task进程](/learn?id=taskworker进程)，传入 Task 进程的`ID`即可，范围为`[0, $server->setting['task_worker_num']-1]`
      * 默认值：-1【默认为`-1`表示随机投递，底层会自动选择一个空闲 [Task进程](/learn?id=taskworker进程)】
      * 其它值：`[0, $server->setting['task_worker_num']-1]`

  * **提示**

    * **协程模式**

      * 从`4.0.4`版本开始`taskwait`方法将支持[协程调度](/coroutine?id=协程调度)，在协程中调用`Server->taskwait()`时将自动进行[协程调度](/coroutine?id=协程调度)，不再阻塞等待。
      * 借助[协程调度](/coroutine?id=协程调度)器，`taskwait`可以实现并发调用。

    * **同步模式**

      * 在同步阻塞模式下，`taskwait`需要使用[UnixSocket](/learn?id=什么是IPC)通信和共享内存，将数据返回给`Worker`进程，这个过程是同步阻塞的。

    * **特例**

      * 如果[onTask](/server/events?id=ontask)中没有任何[同步IO](/learn?id=同步io异步io)操作，底层仅有`2`次进程切换的开销，并不会产生`IO`等待，因此这种情况下 `taskwait` 可以视为非阻塞。实际测试[onTask](/server/events?id=ontask)中仅读写`PHP`数组，进行`10`万次`taskwait`操作，总耗时仅为`1`秒，平均每次消耗为`10`微秒

  * **注意**

  !> -`Swoole\Server::finish`,不要使用`taskwait`  
-`taskwait`方法不能在 [task进程](/learn?id=taskworker进程)中调用

## taskWaitMulti()

并发执行多个`task`异步任务，此方法不支持[协程调度](/coroutine?id=协程调度)，会导致其他协程开始，协程环境下需要用下文的`taskCo`。

```php
Swoole\Server->taskWaitMulti(array $tasks, float $timeout = 0.5): bool|array
```

  * **参数**

    * `array $tasks`

      * 功能：必须为数字索引数组，不支持关联索引数组，底层会遍历`$tasks`将任务逐个投递到 [Task进程](/learn?id=taskworker进程)
      * 默认值：无
      * 其它值：无

    * `float $timeout`

      * 功能：为浮点型，单位为秒
      * 默认值：0.5秒
      * 其它值：无

  * **返回值**

    * 任务完成或超时，返回结果数组。结果数组中每个任务结果的顺序与`$tasks`对应，如：`$tasks[2]`对应的结果为`$result[2]`
    * 某个任务执行超时不会影响其他任务，返回的结果数据中将不包含超时的任务

  * **注意**

  !> -最大并发任务不得超过`1024`

  * **示例**

```php
$tasks[] = mt_rand(1000, 9999); //任务1
$tasks[] = mt_rand(1000, 9999); //任务2
$tasks[] = mt_rand(1000, 9999); //任务3
var_dump($tasks);

//等待所有Task结果返回，超时为10s
$results = $server->taskWaitMulti($tasks, 10.0);

if (!isset($results[0])) {
    echo "任务1执行超时了\n";
}
if (isset($results[1])) {
    echo "任务2的执行结果为{$results[1]}\n";
}
if (isset($results[2])) {
    echo "任务3的执行结果为{$results[2]}\n";
}
```

## taskCo()

并发执行`Task`并进行[协程调度](/coroutine?id=协程调度)，用于支持协程环境下的`taskWaitMulti`功能。

```php
Swoole\Server->taskCo(array $tasks, float $timeout = 0.5): array
```
  
* `$tasks`任务列表，必须为数组。底层会遍历数组，将每个元素作为`task`投递到`Task`进程池
* `$timeout`超时时间，默认为`0.5`秒，当规定的时间内任务没有全部完成，立即中止并返回结果
* 任务完成或超时，返回结果数组。结果数组中每个任务结果的顺序与`$tasks`对应，如：`$tasks[2]`对应的结果为`$result[2]`
* 某个任务执行失败或超时，对应的结果数组项为`false`，如：`$tasks[2]`失败了，那么`$result[2]`的值为`false`

!> 最大并发任务不得超过`1024`  

  * **调度过程**

    * `$tasks`列表中的每个任务会随机投递到一个`Task`工作进程，投递完毕后，`yield`让出当前协程，并设置一个`$timeout`秒的定时器
    * 在`onFinish`中收集对应的任务结果，保存到结果数组中。判断是否所有任务都返回了结果，如果为否，继续等待。如果为是，进行`resume`恢复对应协程的运行，并清除超时定时器
    * 在规定的时间内任务没有全部完成，定时器先触发，底层清除等待状态。将未完成的任务结果标记为`false`，立即`resume`对应协程

  * **示例**

```php
$server = new Swoole\Http\Server("127.0.0.1", 9502, SWOOLE_BASE);

$server->set([
    'worker_num'      => 1,
    'task_worker_num' => 2,
]);

$server->on('Task', function (Swoole\Server $serv, $task_id, $worker_id, $data) {
    echo "#{$serv->worker_id}\tonTask: worker_id={$worker_id}, task_id=$task_id\n";
    if ($serv->worker_id == 1) {
        sleep(1);
    }
    return $data;
});

$server->on('Request', function ($request, $response) use ($server) {
    $tasks[0] = "hello world";
    $tasks[1] = ['data' => 1234, 'code' => 200];
    $result   = $server->taskCo($tasks, 0.5);
    $response->end('Test End, Result: ' . var_export($result, true));
});

$server->start();
```

## finish()

用于在 [Task进程](/learn?id=taskworker进程)中通知`Worker`进程，投递的任务已完成。此函数可以传递结果数据给`Worker`进程。

```php
Swoole\Server->finish(mixed $data)
```

  * **参数**

    * `mixed $data`

      * 功能：任务处理的结果内容
      * 默认值：无
      * 其它值：无

  * **提示**
    * `finish`方法可以连续多次调用，`Worker`进程会多次触发[onFinish](/server/events?id=onfinish)事件
    * 在[onTask](/server/events?id=ontask)回调函数中调用过`finish`方法后，`return`数据依然会触发[onFinish](/server/events?id=onfinish)事件
    * `Server->finish`是可选的。如果`Worker`进程不关心任务执行的结果，不需要调用此函数
    * 在[onTask](/server/events?id=ontask)回调函数中`return`字符串，等同于调用`finish`

  * **注意**

  !> 使用`Server->finish`函数必须为`Server`设置[onFinish](/server/events?id=onfinish)回调函数。此函数只可用于 [Task进程](/learn?id=taskworker进程)的[onTask](/server/events?id=ontask)回调中

## heartbeat()

与[heartbeat_check_interval](/server/setting?id=heartbeat_check_interval)的被动检测不同，此方法主动检测服务器所有连接，并找出已经超过约定时间的连接。如果指定`if_close_connection`，则自动关闭超时的连接。未指定仅返回连接的`fd`数组。

```php
Swoole\Server->heartbeat(bool $ifCloseConnection = true): bool|array
```

  * **参数**

    * `bool $ifCloseConnection`

      * 功能：是否关闭超时的连接
      * 默认值：true
      * 其它值：false

  * **返回值**

    * 调用成功将返回一个连续数组，元素是已关闭的`$fd`
    * 调用失败返回`false`

  * **示例**

```php
$closeFdArrary = $server->heartbeat();
```

## getLastError()

获取最近一次操作错误的错误码。业务代码中可以根据错误码类型执行不同的逻辑。

```php
Swoole\Server->getLastError(): int
```

  * **返回值**

错误码 | 解释
---|---
1001 | 连接已经被`Server`端关闭了，出现这个错误一般是代码中已经执行了`$server->close()`关闭了某个连接，但仍然调用`$server->send()`向这个连接发送数据
1002 | 连接已被`Client`端关闭了，`Socket`已关闭无法发送数据到对端
1003 | 正在执行`close`，[onClose](/server/events?id=onclose)回调函数中不得使用`$server->send()`
1004 | 连接已关闭
1005 | 连接不存在，传入`$fd` 可能是错误的
1007 | 接收到了超时的数据，`TCP`关闭连接后，可能会有部分数据残留在[unixSocket](/learn?id=什么是IPC)缓存区内，这部分数据会被丢弃
1008 | 发送缓存区已满无法执行`send`操作，出现这个错误表示这个连接的对端无法及时收数据导致发送缓存区已塞满
1202 | 发送的数据超过了 [server->buffer_output_size](/server/setting?id=buffer_output_size) 设置
9007 | 仅在使用[dispatch_mode](/server/setting?id=dispatch_mode)=3时出现，表示当前没有可用的进程，可以调大`worker_num`进程数量

## getSocket()

调用此方法可以得到底层的`socket`句柄，返回的对象为`sockets`资源句柄。

```php
Swoole\Server->getSocket()
```

!> 此方法需要依赖PHP的`sockets`扩展，并且编译`Swoole`时需要开启`--enable-sockets`选项

  * **监听端口**

    * 使用`listen`方法增加的端口，可以使用`Swoole\Server\Port`对象提供的`getSocket`方法。

    ```php
    $port = $server->listen('127.0.0.1', 9502, SWOOLE_SOCK_TCP);
    $socket = $port->getSocket();
    ```

    * 使用`socket_set_option`函数可以设置更底层的一些`socket`参数。

    ```php
    $socket = $server->getSocket();
    if (!socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1)) {
        echo 'Unable to set option on socket: '. socket_strerror(socket_last_error()) . PHP_EOL;
    }
    ```

  * **支持组播**

    * 使用`socket_set_option`设置`MCAST_JOIN_GROUP`参数可以将`Socket`加入组播，监听网络组播数据包。

```php
$server = new Swoole\Server('0.0.0.0', 9905, SWOOLE_BASE, SWOOLE_SOCK_UDP);
$server->set(['worker_num' => 1]);
$socket = $server->getSocket();

$ret = socket_set_option(
    $socket,
    IPPROTO_IP,
    MCAST_JOIN_GROUP,
    array(
        'group' => '224.10.20.30', // 表示组播地址
        'interface' => 'eth0' // 表示网络接口的名称，可以为数字或字符串，如eth0、wlan0
    )
);

if ($ret === false) {
    throw new RuntimeException('Unable to join multicast group');
}

$server->on('Packet', function (Swoole\Server $server, $data, $addr) {
    $server->sendto($addr['address'], $addr['port'], "Swoole: $data");
    var_dump($addr, strlen($data));
});

$server->start();
```

## protect()

设置客户端连接为保护状态，不被心跳线程切断。

```php
Swoole\Server->protect(int $fd, bool $value = true)
```

  * **参数**

    * `int $fd`

      * 功能：指定客户端连接`fd`
      * 默认值：无
      * 其它值：无

    * `bool $value`

      * 功能：设置的状态
      * 默认值：true 【表示保护状态】
      * 其它值：false 【表示不保护】

## confirm()

确认连接，与[enable_delay_receive](/server/setting?id=enable_delay_receive)配合使用。当客户端建立连接后，并不监听可读事件，仅触发[onConnect](/server/events?id=onconnect)事件回调，在[onConnect](/server/events?id=onconnect)回调中执行`confirm`确认连接，这时服务器才会监听可读事件，接收来自客户端连接的数据。

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Server->confirm(int $fd)
```

  * **参数**

    * `int $fd`

      * 功能：连接的唯一标识符
      * 默认值：无
      * 其它值：无

  * **返回值**
  
    * 确认成功返回`true`
    * `$fd`对应的连接不存在、已关闭或已经处于监听状态时，返回`false`，确认失败

  * **用途**
  
    此方法一般用于保护服务器，避免收到流量过载攻击。当收到客户端连接时[onConnect](/server/events?id=onconnect)函数触发，可判断来源`IP`，是否允许向服务器发送数据。

  * **示例**
    
```php
//创建Server对象，监听 127.0.0.1:9501端口
$serv = new Swoole\Server("127.0.0.1", 9501); 
$serv->set([
    'enable_delay_receive' => true,
]);

//监听连接进入事件
$serv->on('Connect', function ($serv, $fd) {  
    //在这里检测这个$fd，没问题再confirm
    $serv->confirm($fd);
});

//监听数据接收事件
$serv->on('Receive', function ($serv, $fd, $reactor_id, $data) {
    $serv->send($fd, "Server: ".$data);
});

//监听连接关闭事件
$serv->on('Close', function ($serv, $fd) {
    echo "Client: Close.\n";
});

//启动服务器
$serv->start(); 
```

## getWorkerId()

获取当前`Worker`进程`id`（非进程的`PID`），和[onWorkerStart](/server/events?id=onworkerstart)时的`$workerId`一致

```php
Swoole\Server->getWorkerId(): int|false
```

!> Swoole版本 >= `v4.5.0RC1` 可用

## getWorkerPid()

获取当前`Worker`进程`PID`

```php
Swoole\Server->getWorkerPid(): int|false
```

!> Swoole版本 >= `v4.5.0RC1` 可用

## getWorkerStatus()

获取`Worker`进程状态

```php
Swoole\Server->getWorkerStatus(int $worker_id): int|false
```

!> Swoole版本 >= `v4.5.0RC1` 可用

  * **参数**

    * `int $worker_id`

      * 功能：`Worker`进程`id`
      * 默认值：当前`Worker`进程`id`
      * 其它值：无

  * **返回值**
  
    * 返回`Worker`进程状态，参考进程状态值
    * 不是`Worker`进程或者进程不存在返回`false`

  * **进程状态值**

    常量 | 值 | 说明 | 版本依赖
    ---|---|---|---
    SWOOLE_WORKER_BUSY | 1 | 忙碌 | v4.5.0RC1
    SWOOLE_WORKER_IDLE | 2 | 空闲 | v4.5.0RC1
    SWOOLE_WORKER_EXIT | 3 | [reload_async](/server/setting?id=reload_async)启用的情况下，同一个worker_id可能有2个进程，一个新的一个老的，老进程读取到的状态码是 EXIT。 | v4.5.5

## getManagerPid()

获取当前服务的`Manager`进程`PID`

```php
Swoole\Server->getManagerPid(): int
```

!> Swoole版本 >= `v4.5.0RC1` 可用

## getMasterPid()

获取当前服务的`Master`进程`PID`

```php
Swoole\Server->getMasterPid(): int
```

!> Swoole版本 >= `v4.5.0RC1` 可用

## addCommand()

添加一个`command`

```php
Swoole\Server->addCommand(string $name, int $accepted_process_types, callable $callback): bool
```

!> Swoole版本 >= `v4.8.0` 可用

* **参数**

    * `string $name`

        * 功能：`command` 名称
        * 默认值：无
        * 其它值：无

    * `int $accepted_process_types`

      * 功能：接受请求的进程类型
      * 默认值：无
      * 其它值：`SWOOLE_SERVER_COMMAND_MASTER`、`SWOOLE_SERVER_COMMAND_MANAGER`、`SWOOLE_SERVER_COMMAND_EVENT_WORKER`、`SWOOLE_SERVER_COMMAND_TASK_WORKER`

    * `callable $callback`

          * 功能：回调函数
          * 默认值：无
          * 其它值：无

* **返回值**

    * 返回`Worker`进程状态，参考进程状态值
    * 不是`Worker`进程或者进程不存在返回`false`

## command()

调用`command`

```php
Swoole\Server->command(string $name, int $process_id, int $process_type, $data, bool $json_decode = true)
```

!> Swoole版本 >= `v4.8.0` 可用


* **参数**

    * `string $name`

        * 功能：`command` 名称
        * 默认值：无
        * 其它值：无

    * `int $process_id`

        * 功能：进程ID
        * 默认值：无
        * 其它值：无

    * `int $process_type`

        * 功能：进程请求类型
        * 默认值：无
        * 其它值：`SWOOLE_SERVER_COMMAND_MASTER`、`SWOOLE_SERVER_COMMAND_MANAGER`、`SWOOLE_SERVER_COMMAND_EVENT_WORKER`、`SWOOLE_SERVER_COMMAND_TASK_WORKER`

    * `$data`

        * 功能：请求的数据
        * 默认值：无
        * 其它值：无

    * `bool $json_decode`

          * 功能：是否使用`json_decode`解析
          * 默认值：无
          * 其它值：无
