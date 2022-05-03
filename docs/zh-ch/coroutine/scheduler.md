# Coroutine\Scheduler

?> 所有的[协程](/coroutine)必须在`协程容器`里面[创建](/coroutine/coroutine?id=create)，`Swoole`程序启动的时候大部分情况会自动创建`协程容器`，用`Swoole`启动程序的方式一共有三种：

   - 调用[异步风格](/server/init)服务端程序的[start](/server/methods?id=start)方法，此种启动方式会在事件回调中创建`协程容器`，参考[enable_coroutine](/server/setting?id=enable_coroutine)。
   - 调用`Swoole`提供的2个进程管理模块[Process](/process/process)和[Process\Pool](/process/process_pool)的[start](/process/process_pool?id=start)方法，此种启动方式会在进程启动的时候创建`协程容器`，参考这两个模块构造函数的`enable_coroutine`参数。
   - 其他直接裸写协程的方式启动程序，需要先创建一个协程容器(`Coroutine\run()`函数，可以理解为java、c的`main`函数)，例如：

* **启动一个全协程`HTTP`服务**

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
echo 1;//得不到执行
```

* **添加2个协程并发的做一些事情**

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

run(function () {
    Coroutine::create(function() {
        var_dump(file_get_contents("http://www.xinhuanet.com/"));
    });

    Coroutine::create(function() {
        Coroutine::sleep(1);
        echo "done\n";
    });
});
echo 1;//可以得到执行
```

!> 在`Swoole v4.4+`版本可用。

!> 不可以嵌套`Coroutine\run()`。  
`Coroutine\run()`里面的逻辑如果有未处理的事件在`Coroutine\run()`之后就进行[EventLoop](learn?id=什么是eventloop)，后面的代码将得不到执行，反之，如果没有事件了将继续向下执行，可以再次`Coroutine\run()`。

上文的`Coroutine\run()`函数其实是对`Swoole\Coroutine\Scheduler`类(协程调度器类)的封装，想了解细节的同学可以看`Swoole\Coroutine\Scheduler`的方法：

### set()

?> **设置协程运行时参数。** 

?> 是`Coroutine::set`方法的别名。请参考 [Coroutine::set](/coroutine/coroutine?id=set) 文档

```php
Swoole\Coroutine\Scheduler->set(array $options): bool
```

  * **示例**

```php
$sch = new Swoole\Coroutine\Scheduler;
$sch->set(['max_coroutine' => 100]);
```

### getOptions()

?> **获取设置的协程运行时参数。** Swoole版本 >= `v4.6.0` 可用

?> 是`Coroutine::getOptions`方法的别名。请参考 [Coroutine::getOptions](/coroutine/coroutine?id=getoptions) 文档

```php
Swoole\Coroutine\Scheduler->getOptions(): null|array
```

### add()

?> **添加任务。** 

```php
Swoole\Coroutine\Scheduler->add(callable $fn, ... $args): bool
```

  * **参数** 

    * **`callable $fn`**
      * **功能**：回调函数
      * **默认值**：无
      * **其它值**：无

    * **`... $args`**
      * **功能**：可选参数，将传递给协程
      * **默认值**：无
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine;

$scheduler = new Coroutine\Scheduler;
$scheduler->add(function ($a, $b) {
    Coroutine::sleep(1);
    echo assert($a == 'hello') . PHP_EOL;
    echo assert($b == 12345) . PHP_EOL;
    echo "Done.\n";
}, "hello", 12345);

$scheduler->start();
```
  
  * **注意**

    !> 与`go`函数不同，这里添加的协程不会立即执行，而是等待调用`start`方法时，一起启动并执行。如果程序中仅添加了协程，未调用`start`启动，协程函数`$fn`将不会被执行。

### parallel()

?> **添加并行任务。** 

?> 与`add`方法不同，`parallel`方法会创建并行协程。在`start`时会同时启动`$num`个`$fn`协程，并行地执行。

```php
Swoole\Coroutine\Scheduler->parallel(int $num, callable $fn, ... $args): bool
```

  * **参数** 

    * **`int $num`**
      * **功能**：启动协程的个数
      * **默认值**：无
      * **其它值**：无

    * **`callable $fn`**
      * **功能**：回调函数
      * **默认值**：无
      * **其它值**：无

    * **`... $args`**
      * **功能**：可选参数，将传递给协程
      * **默认值**：无
      * **其它值**：无

  * **示例**

```php
use Swoole\Coroutine;

$scheduler = new Coroutine\Scheduler;

$scheduler->parallel(10, function ($t, $n) {
    Coroutine::sleep($t);
    echo "Co ".Coroutine::getCid()."\n";
}, 0.05, 'A');

$scheduler->start();
```

### start()

?> **启动程序。** 

?> 遍历`add`和`parallel`方法添加的协程任务，并执行。

```php
Swoole\Coroutine\Scheduler->start(): bool
```

  * **返回值**

    * 启动成功，会执行所有添加的任务，所有协程退出时`start`会返回`true`
    * 启动失败返回`false`，原因可能是已经启动了或者已经创建了其他调度器无法再次创建