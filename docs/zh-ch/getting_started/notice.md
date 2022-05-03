# 编程须知

此章节会详细介绍协程编程与同步编程的不同之处以及需要注意的事项。

## 注意事项

* 不要在代码中执行`sleep`以及其他睡眠函数，这样会导致整个进程阻塞；协程中可以使用[Co::sleep()](/coroutine/system?id=sleep)或在[一键协程化](/runtime)后使用`sleep`；参考：[sleep/usleep的影响](/getting_started/notice?id=sleepusleep的影响)
* `exit/die`是危险的，会导致`Worker`进程退出；参考：[exit/die函数的影响](/getting_started/notice?id=exitdie函数的影响)
* 可通过`register_shutdown_function`来捕获致命错误，在进程异常退出时做一些清理工作；参考：[捕获Server运行期致命错误](/getting_started/notice?id=捕获server运行期致命错误)
* `PHP`代码中如果有异常抛出，必须在回调函数中进行`try/catch`捕获异常，否则会导致工作进程退出；参考：[捕获异常和错误](/getting_started/notice?id=捕获异常和错误)
* 不支持`set_exception_handler`，必须使用`try/catch`方式处理异常；
* `Worker`进程不得共用同一个`Redis`或`MySQL`等网络服务客户端，`Redis/MySQL`创建连接的相关代码可以放到`onWorkerStart`回调函数中。参考 [是否可以共用1个Redis或MySQL连接](/question/use?id=是否可以共用1个redis或mysql连接)

## 协程编程

使用`Coroutine`特性，请认真阅读 [协程编程须知](/coroutine/notice)

## 并发编程

请务必注意与`同步阻塞`模式不同，`协程`模式下程序是**并发执行**的，在同一时间内`Server`会存在多个请求，因此**应用程序必须为每个客户端或请求，创建不同的资源和上下文**。否则不同的客户端和请求之间可能会产生数据和逻辑错乱。

## 类/函数重复定义

新手非常容易犯这个错误，由于`Swoole`是常驻内存的，所以加载类/函数定义的文件后不会释放。因此引入类/函数的php文件时必须要使用`include_once`或`require_once`，否则会发生`cannot redeclare function/class` 的致命错误。

## 内存管理

!> 编写`Server`或其他常驻进程时需要特别注意。

`PHP`守护进程与普通`Web`程序的变量生命周期、内存管理方式完全不同。`Server`启动后内存管理的底层原理与普通php-cli程序一致。具体请参考`Zend VM`内存管理方面的文章。

### 局部变量

在事件回调函数返回后，所有局部对象和变量会全部回收，不需要`unset`。如果变量是一个资源类型，那么对应的资源也会被PHP底层释放。

```php
function test()
{
	$a = new Object;
	$b = fopen('/data/t.log', 'r+');
	$c = new swoole_client(SWOOLE_SYNC);
	$d = new swoole_client(SWOOLE_SYNC);
	global $e;
	$e['client'] = $d;
}
```

* `$a`, `$b`, `$c` 都是局部变量，当此函数`return`时，这`3`个变量会立即释放，对应的内存会立即释放，打开的IO资源文件句柄会立即关闭。
* `$d` 也是局部变量，但是`return`前将它保存到了全局变量`$e`，所以不会释放。当执行`unset($e['client'])`时，并且没有任何其他`PHP变量`仍然在引用`$d`变量，那么`$d`就会被释放。

### 全局变量

在`PHP`中，有`3`类全局变量。

* 使用`global`关键词声明的变量
* 使用`static`关键词声明的类静态变量、函数静态变量
* `PHP`的超全局变量，包括`$_GET`、`$_POST`、`$GLOBALS`等

全局变量和对象，类静态变量，保存在`Server`对象上的变量不会被释放。需要程序员自行处理这些变量和对象的销毁工作。

```php
class Test
{
	static $array = array();
	static $string = '';
}

function onReceive($serv, $fd, $reactorId, $data)
{
	Test::$array[] = $fd;
	Test::$string .= $data;
}
```

* 在事件回调函数中需要特别注意非局部变量的`array`类型值，某些操作如  `TestClass::$array[] = "string"` 可能会造成内存泄漏，严重时可能发生内存溢出，必要时应当注意清理大数组。

* 在事件回调函数中，非局部变量的字符串进行拼接操作是必须小心内存泄漏，如 `TestClass::$string .= $data`，可能会有内存泄漏，严重时可能发生内存溢出。

### 解决方法

* 同步阻塞并且请求响应式无状态的`Server`程序可以设置[max_request](/server/setting?id=max_request)和[task_max_request](/server/setting?id=task_max_request)，当 [Worker进程](/learn?id=worker进程) / [Task进程](/learn?id=taskworker进程) 结束运行时或达到任务上限后进程自动退出，该进程的所有变量/对象/资源均会被释放回收。
* 程序内在`onClose`或设置`定时器`及时使用`unset`清理变量，回收资源。

## 进程隔离

进程隔离也是很多新手经常遇到的问题。修改了全局变量的值，为什么不生效？原因就是全局变量在不同的进程，内存空间是隔离的，所以无效。

所以使用`Swoole`开发`Server`程序需要了解`进程隔离`问题，`Swoole\Server`程序的不同`Worker`进程之间是隔离的，在编程时操作全局变量、定时器、事件监听，仅在当前进程内有效。

* 不同的进程中PHP变量不是共享，即使是全局变量，在A进程内修改了它的值，在B进程内是无效的
* 如果需要在不同的Worker进程内共享数据，可以用`Redis`、`MySQL`、`文件`、`Swoole\Table`、`APCu`、`shmget`等工具实现
* 不同进程的文件句柄是隔离的，所以在A进程创建的Socket连接或打开的文件，在B进程内是无效，即使是将它的fd发送到B进程也是不可用的

示例：

```php
$server = new Swoole\Http\Server('127.0.0.1', 9500);

$i = 1;

$server->on('Request', function ($request, $response) {
	global $i;
    $response->end($i++);
});

$server->start();
```

在多进程的服务器中，`$i`变量虽然是全局变量(`global`)，但由于进程隔离的原因。假设有`4`个工作进程，在`进程1`中进行`$i++`，实际上只有`进程1`中的`$i`变成`2`了，其他另外`3`个进程内`$i`变量的值还是`1`。

正确的做法是使用`Swoole`提供的[Swoole\Atomic](/memory/atomic)或[Swoole\Table](/memory/table)数据结构来保存数据。如上述代码可以使用`Swoole\Atomic`实现。

```php
$server = new Swoole\Http\Server('127.0.0.1', 9500);

$atomic = new Swoole\Atomic(1);

$server->on('Request', function ($request, $response) use ($atomic) {
    $response->end($atomic->add(1));
});

$server->start();
```

!> `Swoole\Atomic`数据是建立在共享内存之上的，使用`add`方法加`1`时，在其他工作进程内也是有效的

`Swoole`提供的[Table](/memory/table)、[Atomic](/memory/atomic)、[Lock](/memory/lock)组件是可以用于多进程编程的，但必须在`Server->start`之前创建。另外`Server`维持的`TCP`客户端连接也可以跨进程操作，如`Server->send`和`Server->close`。

## stat缓存清理

PHP底层对`stat`系统调用增加了`Cache`，在使用`stat`、`fstat`、`filemtime`等函数时，底层可能会命中缓存，返回历史数据。

可以使用 [clearstatcache](https://www.php.net/manual/en/function.clearstatcache.php) 函数清理文件`stat`缓存。

## mt_rand随机数

在`Swoole`中如果在父进程内调用了`mt_rand`，不同的子进程内再调用`mt_rand`返回的结果会是相同的，所以必须在每个子进程内调用`mt_srand`重新播种。

!> `shuffle`和`array_rand`等依赖随机数的`PHP`函数同样会受到影响  

示例：

```php
mt_rand(0, 1);

//开始
$worker_num = 16;

//fork 进程
for($i = 0; $i < $worker_num; $i++) {
    $process = new Swoole\Process('child_async', false, 2);
    $pid = $process->start();
}

//异步执行进程
function child_async(Swoole\Process $worker) {
    mt_srand(); //重新播种
    echo mt_rand(0, 100).PHP_EOL;
    $worker->exit();
}
```

## 捕获异常和错误

### 可捕获的异常/错误

在`PHP`大致有三种类型的可捕获的异常/错误

1. `Error`：`PHP`内核抛出错误的专用类型，如类不存在，函数不存在，函数参数错误，都会抛出此类型的错误，`PHP`代码中不应该使用`Error类`来作为异常抛出
2. `Exception`：应用开发者应该使用的异常基类
3. `ErrorException`：此异常基类专门负责将`PHP`的`Warning`/`Notice`等信息通过`set_error_handler`转换成异常，PHP未来的规划必然是将所有的`Warning`/`Notice`转为异常，以便于`PHP`程序能够更好更可控地处理各种错误

!> 以上所有类都实现了`Throwable`接口，也就是说，通过`try {} catch(Throwable $e) {}` 即可捕获所有可抛出的异常/错误

示例1：
```php
try {
	test();
} 
catch(Throwable $e) {
	var_dump($e);
}
```
示例2：
```php
try {
	test();
}
catch (Error $e) {
	var_dump($e);
}
catch(Exception $e) {
	var_dump($e);
}
```

### 不可捕获的致命错误和异常

`PHP`错误的一个重要级别，如异常/错误未捕获时、内存不足时或是一些编译期错误(继承的类不存在)，将会以`E_ERROR`级别抛出一个`Fatal Error`，是在程序发生不可回溯的错误时才会触发的，`PHP`程序无法捕获这样级别的一种错误，只能通过`register_shutdown_function`在后续进行一些处理操作。

### 在协程中捕获运行时异常/错误

在`Swoole4`协程编程中，某个协程的代码中抛出错误，会导致整个进程退出，进程所有协程终止执行。在协程顶层空间可以先进行一次`try/catch`捕获异常/错误，仅终止出错的协程。

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

run(function () {
    Coroutine::create(function () {
        try {
            call_user_func($func);
        }
        catch (Error $e) {
            var_dump($e);
        }
        catch(Exception $e) {
            var_dump($e);
        }
    });

    //协程1的错误不影响协程2
    Coroutine::create(function () {
        Coroutine::sleep(5);
        echo 2;
    });
});
```

### 捕获Server运行期致命错误

`Server`运行期一旦发生致命错误，那客户端连接将无法得到回应。如Web服务器，如果有致命错误应当向客户端发送`HTTP 500`错误信息。

在PHP中可以通过 `register_shutdown_function` + `error_get_last` 2个函数来捕获致命错误，并将错误信息发送给客户端连接。

具体代码示例如下：

```php
$http = new Swoole\Http\Server("127.0.0.1", 9501);
$http->on('request', function ($request, $response) {
    register_shutdown_function(function () use ($response) {
        $error = error_get_last();
        var_dump($error);
        switch ($error['type'] ?? null) {
            case E_ERROR :
            case E_PARSE :
            case E_CORE_ERROR :
            case E_COMPILE_ERROR :
                // log or send:
                // error_log($message);
                // $server->send($fd, $error['message']);
                $response->status(500);
                $response->end($error['message']);
                break;
        }
    });
    exit(0);
});
$http->start();
```

## 使用影响

### sleep/usleep的影响

在异步IO的程序中，**不得使用sleep/usleep/time_sleep_until/time_nanosleep**。（下文中使用`sleep`泛指所有睡眠函数）

* `sleep`函数会使进程陷入睡眠阻塞
* 直到指定的时间后操作系统才会重新唤醒当前的进程
* `sleep`过程中，只有信号可以打断
* 由于`Swoole`的信号处理是基于`signalfd`实现的，所以即使发送信号也无法中断`sleep`

`Swoole`提供的[Swoole\Event::add](/event?id=add)、[Swoole\Timer::tick](/timer?id=tick)、[Swoole\Timer::after](/timer?id=after)、[Swoole\Process::signal](/process/process?id=signal) 在进程`sleep`后会停止工作。[Swoole\Server](/server/tcp_init)也无法再处理新的请求。

#### 示例

```php
$server = new Swoole\Server("127.0.0.1", 9501);
$server->set(['worker_num' => 1]);
$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    sleep(100);
    $server->send($fd, 'Swoole: '.$data);
});
$server->start();
```

!> 在[onReceive](/server/events?id=onreceive)事件中执行了`sleep`函数，`Server`在100秒内无法再收到任何客户端请求。

### exit/die函数的影响

在`Swoole`程序中禁止使用`exit/die`，如果PHP代码中有`exit/die`，当前工作的[Worker进程](/learn?id=worker进程)、[Task进程](/learn?id=taskworker进程)、[User进程](/server/methods?id=addprocess)、以及`Swoole\Process`进程会立即退出。

使用`exit/die`后`Worker`进程会因为异常退出，被`master`进程再次拉起，最终造成进程不断退出又不断启动和产生大量警报日志.

建议使用`try/catch`的方式替换`exit/die`，实现中断执行跳出`PHP`函数调用栈。

```php
Swoole\Coroutine\run(function () {
    try
    {
        exit(0);
    } catch (Swoole\ExitException $e)
    {
        echo $e->getMessage()."\n";
    }
});
```

!> `Swoole\ExitException`是Swoole`v4.1.0`版本及以上直接支持了在协程和`Server`中使用PHP的`exit`，此时底层会自动抛出一个可捕获的`Swoole\ExitException`，开发者可以在需要的位置捕获并实现与原生PHP一样的退出逻辑。具体使用参考[退出协程](/coroutine/notice?id=退出协程);

异常处理的方式比`exit/die`更友好，因为异常是可控的，`exit/die`不可控。在最外层进行`try/catch`即可捕获异常，仅终止当前的任务。`Worker`进程可以继续处理新的请求，而`exit/die`会导致进程直接退出，当前进程保存的所有变量和资源都会被销毁。如果进程内还有其他任务要处理，遇到`exit/die`也将全部丢弃。

### while循环的影响

异步程序如果遇到死循环，事件将无法触发。异步IO程序使用`Reactor模型`，运行过程中必须在`reactor->wait`处轮询。如果遇到死循环，那么程序的控制权就在`while`中了，`reactor`无法得到控制权，无法检测事件，所以IO事件回调函数也将无法触发。

!> 密集运算的代码没有任何IO操作，所以不能称为阻塞  

#### 实例程序

```php
$server = new Swoole\Server('127.0.0.1', 9501);
$server->set(['worker_num' => 1]);
$server->on('receive', function ($server, $fd, $reactorId, $data) {
    $i = 0;
    while(1)
    {
        $i++;
    }
    $server->send($fd, 'Swoole: '.$data);
});
$server->start();
```

!> 在[onReceive](/server/events?id=onreceive)事件中执行了死循环，`server`无法再收到任何客户端请求，必须等待循环结束才能继续处理新的事件。
