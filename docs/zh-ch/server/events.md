# 事件

此节将介绍所有的Swoole的回调函数，每个回调函数都是一个PHP函数，对应一个事件。

### onStart

?> **启动后在主进程（master）的主线程回调此函数**

```php
function onStart(Swoole\Server $server);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

* **在此事件之前`Server`已进行了如下操作**

    * 启动创建完成[Manager 进程](/learn?id=manager进程)
    * 启动创建完成[Worker 子进程](/learn?id=worker进程)
    * 监听所有TCP/UDP/[unixSocket](/learn?id=什么是IPC)端口，但未开始Accept连接和请求
    * 监听了定时器

* **接下来要执行**

    * 主[Reactor](/learn?id=reactor线程)开始接收事件，客户端可以`connect`到`Server`

**`onStart`回调中，仅允许`echo`、打印`Log`、修改进程名称。不得执行其他操作(不能调用`server`相关函数等操作，因为服务尚未就绪)。`onWorkerStart`和`onStart`回调是在不同进程中并行执行的，不存在先后顺序。**

可以在`onStart`回调中，将`$server->master_pid`和`$server->manager_pid`的值保存到一个文件中。这样可以编写脚本，向这两个`PID`发送信号来实现关闭和重启的操作。

`onStart`事件在`Master`进程的主线程中被调用。

!> 在`onStart`中创建的全局资源对象不能在`Worker`进程中被使用，因为发生`onStart`调用时，`worker`进程已经创建好了  
新创建的对象在主进程内，`Worker`进程无法访问到此内存区域  
因此全局对象创建的代码需要放置在`Server::start`之前，典型的例子是[Swoole\Table](/memory/table?id=完整示例)

* **安全提示**

在`onStart`回调中可以使用异步和协程的API，但需要注意这可能会与`dispatch_func`和`package_length_func`存在冲突，**请勿同时使用**。

`onStart`回调在`return`之前服务器程序不会接受任何客户端连接，因此可以安全地使用同步阻塞的函数。

* **BASE 模式**

[SWOOLE_BASE](/learn?id=swoole_base)模式下没有`master`进程，因此不存在`onStart`事件，请不要在`BASE`模式中使用`onStart`回调函数。

```
WARNING swReactorProcess_start: The onStart event with SWOOLE_BASE is deprecated
```

### onBeforeShutdown

?> **此事件在`Server`正常结束前发生** 

!> Swoole版本 >= `v4.8.0` 可用。在此事件中可以使用协程API。

```php
function onBeforeShutdown(Swoole\Server $server);
```


* **参数**

    * **`Swoole\Server $server`**
        * **功能**：Swoole\Server对象
        * **默认值**：无
        * **其它值**：无

### onShutdown

?> **此事件在`Server`正常结束时发生**

```php
function onShutdown(Swoole\Server $server);
```

  * **参数**

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

  * **在此之前`Swoole\Server`已进行了如下操作**

    * 已关闭所有[Reactor](/learn?id=reactor线程)线程、`HeartbeatCheck`线程、`UdpRecv`线程
    * 已关闭所有`Worker`进程、 [Task进程](/learn?id=taskworker进程)、[User进程](/server/methods?id=addprocess)
    * 已`close`所有`TCP/UDP/UnixSocket`监听端口
    * 已关闭主[Reactor](/learn?id=reactor线程)

  !> 强制`kill`进程不会回调`onShutdown`，如`kill -9`  
  需要使用`kill -15`来发送`SIGTERM`信号到主进程才能按照正常的流程终止  
  在命令行中使用`Ctrl+C`中断程序会立即停止，底层不会回调`onShutdown`

  * **注意事项**

  !> 请勿在`onShutdown`中调用任何异步或协程相关`API`，触发`onShutdown`时底层已销毁了所有事件循环设施；  
此时已经不存在协程环境，如果开发者需要使用协程相关`API`需要手动调用`Co\run`来创建[协程容器](/coroutine?id=什么是协程容器)。

### onWorkerStart

?> **此事件在 Worker进程/ [Task进程](/learn?id=taskworker进程) 启动时发生，这里创建的对象可以在进程生命周期内使用。**

```php
function onWorkerStart(Swoole\Server $server, int $workerId);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $workerId`**
      * **功能**：`Worker` 进程 `id`（非进程的 PID）
      * **默认值**：无
      * **其它值**：无

  * `onWorkerStart/onStart`是并发执行的，没有先后顺序
  * 可以通过`$server->taskworker`属性来判断当前是`Worker`进程还是 [Task进程](/learn?id=taskworker进程)
  * 设置了`worker_num`和`task_worker_num`超过`1`时，每个进程都会触发一次`onWorkerStart`事件，可通过判断[$worker_id](/server/properties?id=worker_id)区分不同的工作进程
  * 由 `worker` 进程向 `task` 进程发送任务，`task` 进程处理完全部任务之后通过[onFinish](/server/events?id=onfinish)回调函数通知 `worker` 进程。例如，在后台操作向十万个用户群发通知邮件，操作完成后操作的状态显示为发送中，这时可以继续其他操作，等邮件群发完毕后，操作的状态自动改为已发送。

  下面的示例用于为 Worker 进程/ [Task进程](/learn?id=taskworker进程)重命名。

```php
$server->on('WorkerStart', function ($server, $worker_id){
    global $argv;
    if($worker_id >= $server->setting['worker_num']) {
        swoole_set_process_name("php {$argv[0]} task worker");
    } else {
        swoole_set_process_name("php {$argv[0]} event worker");
    }
});
```

  如果想使用[Reload](/server/methods?id=reload)机制实现代码重载入，必须在`onWorkerStart`中`require`你的业务文件，而不是在文件头部。在`onWorkerStart`调用之前已包含的文件，不会重新载入代码。

  可以将公用的、不易变的php文件放置到`onWorkerStart`之前。这样虽然不能重载入代码，但所有`Worker`是共享的，不需要额外的内存来保存这些数据。
`onWorkerStart`之后的代码每个进程都需要在内存中保存一份

  * `$worker_id`表示这个`Worker`进程的`ID`，范围参考[$worker_id](/server/properties?id=worker_id)
  * [$worker_id](/server/properties?id=worker_id)和进程`PID`没有任何关系，可使用`posix_getpid`函数获取`PID`

  * **协程支持**

    * 在`onWorkerStart`回调函数中会自动创建协程，所以`onWorkerStart`可以调用协程`API`

  * **注意**

    !> 发生致命错误或者代码中主动调用`exit`时，`Worker/Task`进程会退出，管理进程会重新创建新的进程。这可能导致死循环，不停地创建销毁进程

### onWorkerStop

?> **此事件在`Worker`进程终止时发生。在此函数中可以回收`Worker`进程申请的各类资源。**

```php
function onWorkerStop(Swoole\Server $server, int $workerId);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $workerId`**
      * **功能**：`Worker` 进程 `id`（非进程的 PID）
      * **默认值**：无
      * **其它值**：无

  * **注意**

    !> -进程异常结束，如被强制`kill`、致命错误、`core dump`时无法执行`onWorkerStop`回调函数。  
    -请勿在`onWorkerStop`中调用任何异步或协程相关`API`，触发`onWorkerStop`时底层已销毁了所有[事件循环](/learn?id=什么是eventloop)设施。

### onWorkerExit

?> **仅在开启[reload_async](/server/setting?id=reload_async)特性后有效。参见 [如何正确的重启服务](/question/use?id=swoole如何正确的重启服务)**

```php
function onWorkerExit(Swoole\Server $server, int $workerId);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $workerId`**
      * **功能**：`Worker` 进程 `id`（非进程的 PID）
      * **默认值**：无
      * **其它值**：无

  * **注意**

    !> -`Worker`进程未退出，`onWorkerExit`会持续触发  
    -`onWorkerExit`会在`Worker`进程内触发， [Task进程](/learn?id=taskworker进程)中如果存在[事件循环](/learn?id=什么是eventloop)也会触发  
    -在`onWorkerExit`中尽可能地移除/关闭异步的`Socket`连接，最终底层检测到[事件循环](/learn?id=什么是eventloop)中事件监听的句柄数量为`0`时退出进程  
    -当进程没有事件句柄在监听时，进程结束时将不会回调此函数  
    -等待`Worker`进程退出后才会执行`onWorkerStop`事件回调

### onConnect

?> **有新的连接进入时，在worker进程中回调。**

```php
function onConnect(Swoole\Server $server, int $fd, int $reactorId);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $fd`**
      * **功能**：连接的文件描述符
      * **默认值**：无
      * **其它值**：无

    * **`int $reactorId`**
      * **功能**：连接所在的[Reactor](/learn?id=reactor线程)线程`ID`
      * **默认值**：无
      * **其它值**：无

  * **注意**

    !> `onConnect/onClose`这`2`个回调发生在`Worker`进程内，而不是主进程。  
    `UDP`协议下只有[onReceive](/server/events?id=onreceive)事件，没有`onConnect/onClose`事件

    * **[dispatch_mode](/server/setting?id=dispatch_mode) = 1/3**

      * 在此模式下`onConnect/onReceive/onClose`可能会被投递到不同的进程。连接相关的`PHP`对象数据，无法实现在[onConnect](/server/events?id=onconnect)回调初始化数据，[onClose](/server/events?id=onclose)清理数据
      * `onConnect/onReceive/onClose`这3种事件可能会并发执行，可能会带来异常

### onReceive

?> **接收到数据时回调此函数，发生在`worker`进程中。**

```php
function onReceive(Swoole\Server $server, int $fd, int $reactorId, string $data);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $fd`**
      * **功能**：连接的文件描述符
      * **默认值**：无
      * **其它值**：无

    * **`int $reactorId`**
      * **功能**：`TCP`连接所在的[Reactor](/learn?id=reactor线程)线程`ID`
      * **默认值**：无
      * **其它值**：无

    * **`string $data`**
      * **功能**：收到的数据内容，可能是文本或者二进制内容
      * **默认值**：无
      * **其它值**：无

  * **关于`TCP`协议下包完整性，参考[TCP数据包边界问题](/learn?id=tcp数据包边界问题)**

    * 使用底层提供的`open_eof_check/open_length_check/open_http_protocol`等配置可以保证数据包的完整性
    * 不使用底层的协议处理，在[onReceive](/server/events?id=onreceive)后PHP代码中自行对数据分析，合并/拆分数据包。

    例如：代码中可以增加一个 `$buffer = array()`，使用`$fd`作为`key`，来保存上下文数据。 每次收到数据进行字符串拼接，`$buffer[$fd] .= $data`，然后在判断`$buffer[$fd]`字符串是否为一个完整的数据包。

    默认情况下，同一个`fd`会被分配到同一个`Worker`中，所以数据可以拼接起来。使用[dispatch_mode](/server/setting?id=dispatch_mode) = 3时，请求数据是抢占式的，同一个`fd`发来的数据可能会被分到不同的进程，所以无法使用上述的数据包拼接方法。

  * **多端口监听，参考[此节](/server/port)**

    当主服务器设置了协议后，额外监听的端口默认会继承主服务器的设置。需要显式调用`set`方法来重新设置端口的协议。    

    ```php
    $server = new Swoole\Http\Server("127.0.0.1", 9501);
    $port2 = $server->listen('127.0.0.1', 9502, SWOOLE_SOCK_TCP);
    $port2->on('receive', function (Swoole\Server $server, $fd, $reactor_id, $data) {
        echo "[#".$server->worker_id."]\tClient[$fd]: $data\n";
    });
    ```

    这里虽然调用了`on`方法注册了[onReceive](/server/events?id=onreceive)回调函数，但由于没有调用`set`方法覆盖主服务器的协议，新监听的`9502`端口依然使用`HTTP`协议。使用`telnet`客户端连接`9502`端口发送字符串时服务器不会触发[onReceive](/server/events?id=onreceive)。

  * **注意**

    !> 未开启自动协议选项，[onReceive](/server/events?id=onreceive)单次收到的数据最大为`64K`  
    开启了自动协议处理选项，[onReceive](/server/events?id=onreceive)将收到完整的数据包，最大不超过 [package_max_length](/server/setting?id=package_max_length)  
    支持二进制格式，`$data`可能是二进制数据

### onPacket

?> **接收到`UDP`数据包时回调此函数，发生在`worker`进程中。**

```php
function onPacket(Swoole\Server $server, string $data, array $clientInfo);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`string $data`**
      * **功能**：收到的数据内容，可能是文本或者二进制内容
      * **默认值**：无
      * **其它值**：无

    * **`array $clientInfo`**
      * **功能**：客户端信息包括`address/port/server_socket`等多项客户端信息数据，[参考 UDP 服务器](/start/start_udp_server)
      * **默认值**：无
      * **其它值**：无

  * **注意**

    !> 服务器同时监听`TCP/UDP`端口时，收到`TCP`协议的数据会回调[onReceive](/server/events?id=onreceive)，收到`UDP`数据包回调`onPacket`。 服务器设置的`EOF`或`Length`等自动协议处理([参考TCP数据包边界问题](/learn?id=tcp数据包边界问题))，对`UDP`端口是无效的，因为`UDP`包本身存在消息边界，不需要额外的协议处理。

### onClose

?> **`TCP`客户端连接关闭后，在`Worker`进程中回调此函数。**

```php
function onClose(Swoole\Server $server, int $fd, int $reactorId);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $fd`**
      * **功能**：连接的文件描述符
      * **默认值**：无
      * **其它值**：无

    * **`int $reactorId`**
      * **功能**：来自哪个`reactor`线程，主动`close`关闭时为负数
      * **默认值**：无
      * **其它值**：无

  * **提示**

    * **主动关闭**

      * 当服务器主动关闭连接时，底层会设置此参数为`-1`，可以通过判断`$reactorId < 0`来分辨关闭是由服务器端还是客户端发起的。
      * 只有在`PHP`代码中主动调用`close`方法被视为主动关闭

    * **心跳检测**

      * [心跳检测](/server/setting?id=heartbeat_check_interval)是由心跳检测线程通知关闭的, 关闭时[onClose](/server/events?id=onclose)的`$reactorId`参数不为`-1`

  * **注意**

    !> -[onClose](/server/events?id=onclose) 回调函数如果发生了致命错误，会导致连接泄漏。通过 `netstat` 命令会看到大量 `CLOSE_WAIT` 状态的 `TCP` 连接 ，[参考Swoole视频教程](https://course.swoole-cloud.com/course-video/4)  
    -无论由客户端发起`close`还是服务器端主动调用`$server->close()`关闭连接，都会触发此事件。因此只要连接关闭，就一定会回调此函数  
    -[onClose](/server/events?id=onclose)中依然可以调用[getClientInfo](/server/methods?id=getClientInfo)方法获取到连接信息，在[onClose](/server/events?id=onclose)回调函数执行完毕后才会调用`close`关闭`TCP`连接  
    -这里回调[onClose](/server/events?id=onclose)时表示客户端连接已经关闭，所以无需执行`$server->close($fd)`。代码中执行`$server->close($fd)`会抛出`PHP`错误警告。

### onTask

?> **在`task`进程内被调用。`worker`进程可以使用[task](/server/methods?id=task)函数向`task_worker`进程投递新的任务。当前的 [Task进程](/learn?id=taskworker进程)在调用[onTask](/server/events?id=ontask)回调函数时会将进程状态切换为忙碌，这时将不再接收新的Task，当[onTask](/server/events?id=ontask)函数返回时会将进程状态切换为空闲然后继续接收新的`Task`。**

```php
function onTask(Swoole\Server $server, int $task_id, int $src_worker_id, mixed $data);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $task_id`**
      * **功能**：执行任务的 `task` 进程 `id`【`$task_id`和`$src_worker_id`组合起来才是全局唯一的，不同的`worker`进程投递的任务`ID`可能会有相同】
      * **默认值**：无
      * **其它值**：无

    * **`int $src_worker_id`**
      * **功能**：投递任务的 `worker` 进程 `id`【`$task_id`和`$src_worker_id`组合起来才是全局唯一的，不同的`worker`进程投递的任务`ID`可能会有相同】
      * **默认值**：无
      * **其它值**：无

    * **`mixed $data`**
      * **功能**：任务的数据内容
      * **默认值**：无
      * **其它值**：无

  * **提示**

    * **v4.2.12起如果开启了 [task_enable_coroutine](/server/setting?id=task_enable_coroutine) 则回调函数原型是**

      ```php
      $server->on('Task', function (Swoole\Server $server, Swoole\Server\Task $task) {
          var_dump($task);
          $task->finish([123, 'hello']); //完成任务，结束并返回数据
      });
      ```

    * **返回执行结果到`worker`进程**

      * **在[onTask](/server/events?id=ontask)函数中 `return` 字符串，表示将此内容返回给 `worker` 进程。`worker` 进程中会触发 [onFinish](/server/events?id=onfinish) 函数，表示投递的 `task` 已完成，当然你也可以通过 `Swoole\Server->finish()` 来触发 [onFinish](/server/events?id=onfinish) 函数，而无需再 `return`**

      * `return` 的变量可以是任意非 `null` 的 `PHP` 变量

  * **注意**

    !> [onTask](/server/events?id=ontask)函数执行时遇到致命错误退出，或者被外部进程强制`kill`，当前的任务会被丢弃，但不会影响其他正在排队的`Task`

### onFinish

?> **此回调函数在worker进程被调用，当`worker`进程投递的任务在`task`进程中完成时， [task进程](/learn?id=taskworker进程)会通过`Swoole\Server->finish()`方法将任务处理的结果发送给`worker`进程。**

```php
function onFinish(Swoole\Server $server, int $task_id, mixed $data)
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $task_id`**
      * **功能**：执行任务的 `task` 进程 `id`
      * **默认值**：无
      * **其它值**：无

    * **`mixed $data`**
      * **功能**：任务处理的结果内容
      * **默认值**：无
      * **其它值**：无

  * **注意**

    !> - [task进程](/learn?id=taskworker进程)的[onTask](/server/events?id=ontask)事件中没有调用`finish`方法或者`return`结果，`worker`进程不会触发[onFinish](/server/events?id=onfinish)  
    -执行[onFinish](/server/events?id=onfinish)逻辑的`worker`进程与下发`task`任务的`worker`进程是同一个进程

### onPipeMessage

?> **当工作进程收到由 `$server->sendMessage()` 发送的[unixSocket](/learn?id=什么是IPC)消息时会触发 `onPipeMessage` 事件。`worker/task` 进程都可能会触发 `onPipeMessage` 事件**

```php
function onPipeMessage(Swoole\Server $server, int $src_worker_id, mixed $message);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $src_worker_id`**
      * **功能**：消息来自哪个`Worker`进程
      * **默认值**：无
      * **其它值**：无

    * **`mixed $message`**
      * **功能**：消息内容，可以是任意PHP类型
      * **默认值**：无
      * **其它值**：无

### onWorkerError

?> **当`Worker/Task`进程发生异常后会在`Manager`进程内回调此函数。**

!> 此函数主要用于报警和监控，一旦发现Worker进程异常退出，那么很有可能是遇到了致命错误或者进程Core Dump。通过记录日志或者发送报警的信息来提示开发者进行相应的处理。

```php
function onWorkerError(Swoole\Server $server, int $worker_id, int $worker_pid, int $exit_code, int $signal);
```

  * **参数** 

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

    * **`int $worker_id`**
      * **功能**：异常 `worker` 进程的 `id`
      * **默认值**：无
      * **其它值**：无

    * **`int $worker_pid`**
      * **功能**：异常 `worker` 进程的 `pid`
      * **默认值**：无
      * **其它值**：无

    * **`int $exit_code`**
      * **功能**：退出的状态码，范围是 `0～255`
      * **默认值**：无
      * **其它值**：无

    * **`int $signal`**
      * **功能**：进程退出的信号
      * **默认值**：无
      * **其它值**：无

  * **常见错误**

    * `signal = 11`：说明`Worker`进程发生了`segment fault`段错误，可能触发了底层的`BUG`，请收集`core dump`信息和`valgrind`内存检测日志，[向Swoole开发组反馈此问题](/other/issue)
    * `exit_code = 255`：说明Worker进程发生了`Fatal Error`致命错误，请检查PHP的错误日志，找到存在问题的PHP代码，进行解决
    * `signal = 9`：说明`Worker`被系统强行`Kill`，请检查是否有人为的`kill -9`操作，检查`dmesg`信息中是否存在`OOM（Out of memory）`
    * 如果存在`OOM`，分配了过大的内存。1.检查`Server`的`setting`配置，是否[socket_buffer_size](/server/setting?id=socket_buffer_size)等分配过大；2.是否创建了非常大的[Swoole\Table](/memory/table)内存模块。

### onManagerStart

?> **当管理进程启动时触发此事件**

```php
function onManagerStart(Swoole\Server $server);
```

  * **提示**

    * 在这个回调函数中可以修改管理进程的名称。
    * 在`4.2.12`以前的版本中`manager`进程中不能添加定时器，不能投递task任务、不能用协程。
    * 在`4.2.12`或更高版本中`manager`进程可以使用基于信号实现的同步模式定时器
    * `manager`进程中可以调用[sendMessage](/server/methods?id=sendMessage)接口向其他工作进程发送消息

    * **启动顺序**

      * `Task`和`Worker`进程已创建
      * `Master`进程状态不明，因为`Manager`与`Master`是并行的，`onManagerStart`回调发生是不能确定`Master`进程是否已就绪

    * **BASE 模式**

      * 在[SWOOLE_BASE](/learn?id=swoole_base) 模式下，如果设置了`worker_num`、`max_request`、`task_worker_num`参数，底层将创建`manager`进程来管理工作进程。因此会触发`onManagerStart`和`onManagerStop`事件回调。

### onManagerStop

?> **当管理进程结束时触发**

```php
function onManagerStop(Swoole\Server $server);
```

 * **提示**

  * `onManagerStop`触发时，说明`Task`和`Worker`进程已结束运行，已被`Manager`进程回收。

### onBeforeReload

?> **Worker进程`Reload`之前触发此事件，在Manager进程中回调**

```php
function onBeforeReload(Swoole\Server $server);
```

  * **参数**

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

### onAfterReload

?> **Worker进程`Reload`之后触发此事件，在Manager进程中回调**

```php
function onAfterReload(Swoole\Server $server);
```

  * **参数**

    * **`Swoole\Server $server`**
      * **功能**：Swoole\Server对象
      * **默认值**：无
      * **其它值**：无

### 事件执行顺序

* 所有事件回调均在`$server->start`后发生
* 服务器关闭程序终止时最后一次事件是`onShutdown`
* 服务器启动成功后，`onStart/onManagerStart/onWorkerStart`会在不同的进程内并发执行
* `onReceive/onConnect/onClose`在`Worker`进程中触发
* `Worker/Task`进程启动/结束时会分别调用一次`onWorkerStart/onWorkerStop`
* [onTask](/server/events?id=ontask)事件仅在 [task进程](/learn?id=taskworker进程)中发生
* [onFinish](/server/events?id=onfinish)事件仅在`worker`进程中发生
* `onStart/onManagerStart/onWorkerStart` `3`个事件的执行顺序是不确定的

### 回调对象

启用[event_object](/server/setting?id=event_object)后，以下事件回调将使用对象风格

#### Swoole\Server\Event

* [onConnect](/server/events?id=onconnect)
* [onReceive](/server/events?id=onreceive)
* [onClose](/server/events?id=onclose)

```php
$server->on('Connect', function (Swoole\Server $serv, Swoole\Server\Event $object) {
    var_dump($object);
});
```

#### Swoole\Server\Packet

* [onPacket](/server/events?id=onpacket)

```php
$server->on('Packet', function (Swoole\Server $serv, Swoole\Server\Packet $object) {
    var_dump($object);
});
```

#### Swoole\Server\PipeMessage

* [onPipeMessage](/server/events?id=onpipemessage)

```php
$server->on('PipeMessage', function (Swoole\Server $serv, Swoole\Server\PipeMessage $msg) {
    var_dump($msg);
    $object = $msg->data;
    $serv->sendto($object->address, $object->port, $object->data, $object->server_socket);
});
```

#### Swoole\Server\StatusInfo

* [onWorkerError](/server/events?id=onworkererror)

```php
$serv->on('WorkerError', function (Swoole\Server $serv, Swoole\Server\StatusInfo $info) {
    var_dump($info);
});
```

#### Swoole\Server\Task

* [onTask](/server/events?id=ontask)

```php
$server->on('Task', function (Swoole\Server $serv, Swoole\Server\Task $task) {
    var_dump($task);
});
```

#### Swoole\Server\TaskResult

* [onFinish](/server/events?id=onfinish)

```php
$server->on('Finish', function (Swoole\Server $serv, Swoole\Server\TaskResult $result) {
    var_dump($result);
});
```