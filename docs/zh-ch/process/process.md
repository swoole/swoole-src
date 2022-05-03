# Process

Swoole提供的进程管理模块，用来替代PHP的`pcntl`  

!> 此模块比较底层，是操作系统进程管理的封装，使用者需要具备`Linux`系统多进程编程经验。

`PHP`自带的`pcntl`，存在很多不足，如：

* 没有提供进程间通信的功能
* 不支持重定向标准输入和输出
* 只提供了`fork`这样原始的接口，容易使用错误

`Process`提供了比`pcntl`更强大的功能，更易用的`API`，使PHP在多进程编程方面更加轻松。

`Process`提供了如下特性：

* 可以方便的实现进程间通讯
* 支持重定向标准输入和输出，在子进程内`echo`不会打印屏幕，而是写入管道，读键盘输入可以重定向为管道读取数据
* 提供了[exec](/process/process?id=exec)接口，创建的进程可以执行其他程序，与原`PHP`父进程之间可以方便的通信
* 在协程环境中无法使用`Process`模块，可以使用`runtime hook`+`proc_open`实现，参考[协程进程管理](/coroutine/proc_open)

### 使用示例

  * 创建3个子进程，主进程用wait回收进程
  * 主进程异常退出时，子进程会继续执行，完成所有任务后退出

```php
use Swoole\Process;

for ($n = 1; $n <= 3; $n++) {
    $process = new Process(function () use ($n) {
        echo 'Child #' . getmypid() . " start and sleep {$n}s" . PHP_EOL;
        sleep($n);
        echo 'Child #' . getmypid() . ' exit' . PHP_EOL;
    });
    $process->start();
}
for ($n = 3; $n--;) {
    $status = Process::wait(true);
    echo "Recycled #{$status['pid']}, code={$status['code']}, signal={$status['signal']}" . PHP_EOL;
}
echo 'Parent #' . getmypid() . ' exit' . PHP_EOL;
```

## 属性

### pid

子进程的`PID`。

```php
Swoole\Process->pid: int
```

### pipe

[unixSocket](/learn?id=什么是IPC)的文件描述符。

```php
Swoole\Process->pipe;
```

## 方法

### __construct()

构造方法。

```php
Swoole\Process::__construct(callable $function, bool $redirect_stdin_stdout = false, int $pipe_type = SOCK_DGRAM, bool $enable_coroutine = false);
```

* **参数** 

  * **`callable $function`**
    * **功能**：子进程创建成功后要执行的函数【底层会自动将函数保存到对象的`callback`属性上】
    * **默认值**：无
    * **其它值**：无

  * **`bool $redirect_stdin_stdout`**
    * **功能**：重定向子进程的标准输入和输出。【启用此选项后，在子进程内输出内容将不是打印屏幕，而是写入到主进程管道。读取键盘输入将变为从管道中读取数据。默认为阻塞读取。参考[exec()](/process/process?id=exec)方法内容】
    * **默认值**：无
    * **其它值**：无

  * **`int $pipe_type`**
    * **功能**：[unixSocket](/learn?id=什么是IPC)类型【启用`$redirect_stdin_stdout`后，此选项将忽略用户参数，强制为`1`。如果子进程内没有进程间通信，可以设置为 `0`】
    * **默认值**：`2`
    * **其它值**：`0`、`1`

  * **`bool $enable_coroutine`**
    * **功能**：在`callback function`中启用协程，开启后可以直接在子进程的函数中使用协程API
    * **默认值**：`false`
    * **其它值**：`true`
    * **版本影响**：Swoole版本 >= v4.3.0

* **[unixSocket](/learn?id=什么是IPC)类型**

unixSocket类型 | 说明
---|---
0 | 不创建
1 | 创建[SOCK_STREAM](/learn?id=什么是IPC)类型的unixSocket
2 | 创建[SOCK_DGRAM](/learn?id=什么是IPC)类型的unixSocket

### set()

设置参数。

```php
Swoole\Process->set(array $settings)
```

可以使用`enable_coroutine`来控制是否启用协程，和构造函数的第四个参数作用一致。

```php
Swoole\Process->set(['enable_coroutine' => true]);
```

!> Swoole版本 >= v4.4.4 可用

### start()

执行`fork`系统调用，启动子进程。在`Linux`系统下创建一个进程需要数百微秒时间。

```php
Swoole\Process->start(): int|false
```

* **返回值**

  * 成功返回子进程的`PID`
  * 失败返回`false`。可使用[swoole_errno](/functions?id=swoole_errno)和[swoole_strerror](/functions?id=swoole_strerror)得到错误码和错误信息。

* **注意**

  * 子进程会继承父进程的内存和文件句柄
  * 子进程在启动时会清除从父进程继承的[EventLoop](/learn?id=什么是eventloop)、[Signal](/process/process?id=signal)、[Timer](/timer)
  
  !> 执行后子进程会保持父进程的内存和资源，如父进程内创建了一个redis连接，那么在子进程会保留此对象，所有操作都是对同一个连接进行的。以下举例说明

```php
$redis = new Redis;
$redis->connect('127.0.0.1', 6379);

function callback_function() {
    swoole_timer_after(1000, function () {
        echo "hello world\n";
    });
    global $redis;//同一个连接
};

swoole_timer_tick(1000, function () {
    echo "parent timer\n";
});//不会继承

Swoole\Process::signal(SIGCHLD, function ($sig) {
    while ($ret = Swoole\Process::wait(false)) {
        // create a new child process
        $p = new Swoole\Process('callback_function');
        $p->start();
    }
});

// create a new child process
$p = new Swoole\Process('callback_function');

$p->start();
```

!> 1. 子进程启动后会自动清除父进程中[Swoole\Timer::tick](/timer?id=tick)创建的定时器、[Process::signal](/process/process?id=signal)监听的信号和[Swoole\Event::add](/event?id=add)添加的事件监听；  
2. 子进程会继承父进程创建的`$redis`连接对象，父子进程使用的连接是同一个。

### exportSocket()

将`unixSocket`导出为`Coroutine\Socket`对象，然后利用`Coroutine\socket`对象的方法进程间通讯，具体用法请参考[Coroutine\socket](/coroutine_client/socket)和[IPC通讯](/learn?id=什么是IPC)。

```php
Swoole\Process->exportSocket(): Swoole\Coroutine\Socket|false
```

!> 多次调用此方法，返回的对象是同一个；  
`exportSocket()`导出的`socket`是一个新的`fd`，当关闭导出的`socket`时不会影响进程原有的管道。  
由于是`Coroutine\Socket`对象，必须在[协程容器](/coroutine/scheduler)中使用，所以Swoole\Process构造函数`$enable_coroutine`参数必须为true。  
同样的父进程想用`Coroutine\Socket`对象，需要手动`Coroutine\run()`以创建协程容器。

* **返回值**

  * 成功返回`Coroutine\Socket`对象
  * 进程未创建unixSocket，操作失败，返回`false`

* **使用示例**

实现了一个简单的父子进程通讯：  

```php
use Swoole\Process;
use function Swoole\Coroutine\run;

$proc1 = new Process(function (Process $proc) {
    $socket = $proc->exportSocket();
    echo $socket->recv();
    $socket->send("hello master\n");
    echo "proc1 stop\n";
}, false, 1, true);

$proc1->start();

//父进程创建一个协程容器
run(function() use ($proc1) {
    $socket = $proc1->exportSocket();
    $socket->send("hello pro1\n");
    var_dump($socket->recv());
});
Process::wait(true);
```

比较复杂的通讯例子：

```php
use Swoole\Process;
use Swoole\Timer;
use function Swoole\Coroutine\run;

$process = new Process(function ($proc) {
    Timer::tick(1000, function () use ($proc) {
        $socket = $proc->exportSocket();
        $socket->send("hello master\n");
        echo "child timer\n";
    });
}, false, 1, true);

$process->start();

run(function() use ($process) {
    Process::signal(SIGCHLD, static function ($sig) {
        while ($ret = Swoole\Process::wait(false)) {
            /* clean up then event loop will exit */
            Process::signal(SIGCHLD, null);
            Timer::clearAll();
        }
    });
    /* your can run your other async or coroutine code here */
    Timer::tick(500, function () {
        echo "parent timer\n";
    });

    $socket = $process->exportSocket();
    while (1) {
        var_dump($socket->recv());
    }
});
```
!> 注意默认类型是`SOCK_STREAM`，需要处理TCP数据包边界问题，参考[Coroutine\socket](/coroutine_client/socket)的`setProtocol()`方法。  

使用`SOCK_DGRAM`类型进行IPC通讯，可以避免处理TCP数据包边界问题，参考[IPC通讯](/learn?id=什么是IPC)：

```php
use Swoole\Process;
use function Swoole\Coroutine\run;

//IPC通讯即使是 SOCK_DGRAM 类型的socket也不需要用 sendto / recvfrom 这组函数，send/recv即可。
$proc1 = new Process(function (Process $proc) {
    $socket = $proc->exportSocket();
    while (1) {
        var_dump($socket->send("hello master\n"));
    }
    echo "proc1 stop\n";
}, false, 2, 1);//构造函数pipe type传为2 即SOCK_DGRAM

$proc1->start();

run(function() use ($proc1) {
    $socket = $proc1->exportSocket();
    Swoole\Coroutine::sleep(5);
    var_dump(strlen($socket->recv()));//一次recv只会收到一个"hello master\n"字符串 不会出现多个"hello master\n"字符串
});

Process::wait(true);
```

### name()

修改进程名称。此函数是[swoole_set_process_name](/functions?id=swoole_set_process_name)的别名。

```php
Swoole\Process->name(string $name): bool
```

!> 在执行`exec`后，进程名称会被新的程序重新设置；`name`方法应当在`start`之后的子进程回调函数中使用。

### exec()

执行一个外部程序，此函数是`exec`系统调用的封装。

```php
Swoole\Process->exec(string $execfile, array $args);
```

* **参数** 

  * **`string $execfile`**
    * **功能**：指定可执行文件的绝对路径，如 `"/usr/bin/python"`
    * **默认值**：无
    * **其它值**：无

  * **`array $args`**
    * **功能**：`exec`的参数列表【如 `array('test.py', 123)`，相当于`python test.py 123`】
    * **默认值**：无
    * **其它值**：无

执行成功后，当前进程的代码段将会被新程序替换。子进程蜕变成另外一套程序。父进程与当前进程仍然是父子进程关系。

父进程与新进程之间可以通过标准输入输出进行通信，必须启用标准输入输出重定向。

!> `$execfile`必须使用绝对路径，否则会报文件不存在错误；  
由于`exec`系统调用会使用指定的程序覆盖当前程序，子进程需要读写标准输出与父进程进行通信；  
如果未指定`redirect_stdin_stdout = true`，执行`exec`后子进程与父进程无法通信。

* **使用示例**

例 1：可以在 `Swoole\Process` 创建的子进程中使用 [Swoole\Server](/server/init)，但为了安全必须在`$process->start` 创建进程后，调用 `$worker->exec()` 执行。代码如下：

```php
$process = new Swoole\Process('callback_function', true);

$pid = $process->start();

function callback_function(Swoole\Process $worker)
{
    $worker->exec('/usr/local/bin/php', array(__DIR__.'/swoole_server.php'));
}

Swoole\Process::wait();
```

例 2：启动Yii程序

```php
$process = new \Swoole\Process(function (\Swoole\Process $childProcess) {
    // 不支持这种写法
    // $childProcess->exec('/usr/local/bin/php /var/www/project/yii-best-practice/cli/yii t/index -m=123 abc xyz');

    // 封装 exec 系统调用
    // 绝对路径
    // 参数必须分开放到数组中
    $childProcess->exec('/usr/local/bin/php', ['/var/www/project/yii-best-practice/cli/yii', 't/index', '-m=123', 'abc', 'xyz']); // exec 系统调用
});
$process->start(); // 启动子进程
```

例3：父进程与`exec`子进程使用标准输入输出进行通信:

```php
// exec - 与exec进程进行管道通信
use Swoole\Process;
use function Swoole\Coroutine\run;

$process = new Process(function (Process $worker) {
    $worker->exec('/bin/echo', ['hello']);
}, true, 1, true); // 需要启用标准输入输出重定向

$process->start();

run(function() use($process) {
    $socket = $process->exportSocket();
    echo "from exec: " . $socket->recv() . "\n";
});
```

例4：执行 shell 命令

`exec`方法与`PHP`提供的`shell_exec`不同，它是更底层的系统调用封装。如果需要执行一条`shell`命令，请使用以下方法：

```php
$worker->exec('/bin/sh', array('-c', "cp -rf /data/test/* /tmp/test/"));
```

### close()

用于关闭创建的好的[unixSocket](/learn?id=什么是IPC)。 

```php
Swoole\Process->close(int $which): bool
```

* **参数** 

  * **`int $which`**
    * **功能**：由于unixSocket是全双工的，指定关闭哪一端【默认为`0`表示同时关闭读和写，`1`：关闭写，`2`关闭读】
    * **默认值**：`0`
    * **其它值**：无

!> 有一些特殊的情况`Process`对象无法释放，如果持续创建进程会导致连接泄漏。调用此函数就可以直接关闭`unixSocket`，释放资源。

### exit()

退出子进程。

```php
Swoole\Process->exit(int $status = 0);
```

* **参数** 

  * **`int $status`**
    * **功能**：退出进程的状态码【如果为`0`表示正常结束，会继续执行清理工作】
    * **默认值**：`0`
    * **其它值**：无

!> 清理工作包括：

  * `PHP`的`shutdown_function`
  * 对象析构（`__destruct`）
  * 其他扩展的`RSHUTDOWN`函数

如果`$status`不为`0`，表示异常退出，会立即终止进程，不再执行相关进程终止的清理工作。

在父进程中，执行`Process::wait`可以得到子进程退出的事件和状态码。

### kill()

向指定`pid`进程发送信号。

```php
Swoole\Process::kill(int $pid, int $signo = SIGTERM): bool
```

* **参数** 

  * **`int $pid`**
    * **功能**：进程 `pid`
    * **默认值**：无
    * **其它值**：无

  * **`int $signo`**
    * **功能**：发送的信号【`$signo=0`，可以检测进程是否存在，不会发送信号】
    * **默认值**：`SIGTERM`
    * **其它值**：无

### signal()

设置异步信号监听。

```php
Swoole\Process::signal(int $signo, callable $callback): bool
```

此方法基于`signalfd`和[EventLoop](/learn?id=什么是eventloop)是异步`IO`，不能用于阻塞的程序中，会导致注册的监听回调函数得不到调度；

同步阻塞的程序可以使用`pcntl`扩展提供的`pcntl_signal`；

如果已设置了此信号的回调函数，重新设置时会覆盖历史设置。

* **参数** 

  * **`int $signo`**
    * **功能**：信号
    * **默认值**：无
    * **其它值**：无

  * **`callable $callback`**
    * **功能**：回调函数【`$callback`如果为`null`，表示移除信号监听】
    * **默认值**：无
    * **其它值**：无

!> 在[Swoole\Server](/server/init)中不能设置某些信号监听，如`SIGTERM`和`SIGALAM`

* **使用示例**

```php
Swoole\Process::signal(SIGTERM, function($signo) {
     echo "shutdown.";
});
```

!> 在`v4.4.0`版本中如果进程的[EventLoop](/learn?id=什么是eventloop)中只有信号监听的事件，没有其他事件(例如Timer定时器等)，进程会直接退出。

```php
Swoole\Process::signal(SIGTERM, function($signo) {
     echo "shutdown.";
});
Swoole\Event::wait();
```

上述程序不会进入[EventLoop](/learn?id=什么是eventloop)，`Swoole\Event::wait()`将立即返回，并退出进程。

### wait()

回收结束运行的子进程。

!> Swoole 版本 >= `v4.5.0` 时推荐使用协程版本的`wait()`，参考[Swoole\Coroutine\System::wait()](/coroutine/system?id=wait)

```php
Swoole\Process::wait(bool $blocking = true): array|false
```

* **参数** 

  * **`bool $blocking`**
    * **功能**：指定是否阻塞等待【默认为阻塞】
    * **默认值**：`true`
    * **其它值**：`false`

* **返回值**

  * 操作成功会返回一个数组包含子进程的`PID`、退出状态码、被哪种信号`KILL`
  * 失败返回`false`

!> 每个子进程结束后，父进程必须都要执行一次`wait()`进行回收，否则子进程会变成僵尸进程，会浪费操作系统的进程资源。  
如果父进程有其他任务要做，没法阻塞`wait`在那里，父进程必须注册信号`SIGCHLD`对退出的进程执行`wait`。  
SIGCHILD信号发生时可能同时有多个子进程退出；必须将`wait()`设置为非阻塞，循环执行`wait`直到返回`false`。

* **示例**

```php
Swoole\Process::signal(SIGCHLD, function ($sig) {
    //必须为false，非阻塞模式
    while ($ret = Swoole\Process::wait(false)) {
        echo "PID={$ret['pid']}\n";
    }
});
```

### daemon()

使当前进程蜕变为一个守护进程。

```php
Swoole\Process::daemon(bool $nochdir = true, bool $noclose = true): bool
```

* **参数** 

  * **`bool $nochdir`**
    * **功能**：是否切换当前目录到根目录【为`true`表示不要切换当前目录到根目录】
    * **默认值**：`true`
    * **其它值**：`false`

  * **`bool $noclose`**
    * **功能**：是否要关闭标准输入输出文件描述符【为`true`表示不要关闭标准输入输出文件描述符】
    * **默认值**：`true`
    * **其它值**：`false`

!> 蜕变为守护进程时，该进程的`PID`将发生变化，可以使用`getmypid()`来获取当前的`PID`

### alarm()

高精度定时器，是操作系统`setitimer`系统调用的封装，可以设置微秒级别的定时器。定时器会触发信号，需要与[Process::signal](/process/process?id=signal)或`pcntl_signal`配合使用。

!> `alarm`不能和 [Timer](/timer) 同时使用

```php
Swoole\Process::alarm(int $time, int $type = 0): bool
```

* **参数** 

  * **`int $time`**
    * **功能**：定时器间隔时间【如果为负数表示清除定时器】
    * **值单位**：微秒
    * **默认值**：无
    * **其它值**：无

  * **`int $type`**
    * **功能**：定时器类型
    * **默认值**：`0`
    * **其它值**：

定时器类型 | 说明
---|---
0 | 表示为真实时间，触发`SIGALAM`信号
1 | 表示用户态CPU时间，触发`SIGVTALAM`信号
2 | 表示用户态+内核态时间，触发`SIGPROF`信号

* **返回值**

  * 设置成功返回`true`
  * 失败返回`false`，可以使用`swoole_errno`得到错误码

* **使用示例**

```php
use Swoole\Process;
use function Swoole\Coroutine\run;

run(function () {
    Process::signal(SIGALRM, function () {
        static $i = 0;
        echo "#{$i}\talarm\n";
        $i++;
        if ($i > 20) {
            Process::alarm(-1);
            Process::kill(getmypid());
        }
    });

    //100ms
    Process::alarm(100 * 1000);

    while(true) {
        sleep(0.5);
    }
});
```

### setAffinity()

设置`CPU`亲和性，可以将进程绑定到特定的`CPU`核上。 

此函数的作用是让进程只在某几个`CPU`核上运行，让出某些`CPU`资源执行更重要的程序。

```php
Swoole\Process::setAffinity(array $cpus): bool
```

* **参数** 

  * **`array $cpus`**
    * **功能**：绑定`CPU`核 【如`array(0,2,3)`表示绑定`CPU0/CPU2/CPU3`】
    * **默认值**：无
    * **其它值**：无

!> -`$cpus`内的元素不能超过`CPU`核数；  
-`CPU-ID`不得超过（`CPU`核数 - `1`）；  
-使用 [swoole_cpu_num()](/functions?id=swoole_cpu_num) 可以得到当前服务器的`CPU`核数。

### setPriority()

设置进程、进程组和用户进程的优先级。

!> Swoole版本 >= `v4.5.9` 可用

```php
Swoole\Process->setPriority(int $which, int $priority): bool
```

* **参数** 

  * **`int $which`**
    * **功能**：决定修改优先级的类型
    * **默认值**：无
    * **其它值**：

| 常量         | 说明     |
| ------------ | -------- |
| PRIO_PROCESS | 进程     |
| PRIO_PGRP    | 进程组   |
| PRIO_USER    | 用户进程 |

  * **`int $priority`**
    * **功能**：优先级。值越小，优先级越高
    * **默认值**：无
    * **其它值**：`[-20, 20]`

* **返回值**

  * 如果返回`false`，可使用[swoole_errno](/functions?id=swoole_errno)和[swoole_strerror](/functions?id=swoole_strerror)得到错误码和错误信息。

### getPriority()

获取进程的优先级。

!> Swoole版本 >= `v4.5.9` 可用

```php
Swoole\Process->getPriority(int $which): int
```