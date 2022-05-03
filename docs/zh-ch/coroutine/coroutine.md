# 协程API

> 建议先看[概览](/coroutine)，了解协程基本概念再看此节。

## 方法

### set()

协程设置，设置协程相关选项。

```php
Swoole\Coroutine::set(array $options);
```

参数 | 此版本后稳定 | 作用 
---|---|---
max_coroutine | - | 设置全局最大协程数，超过限制后底层将无法创建新的协程，Server下会被[server->max_coroutine](/server/setting?id=max_coroutine)覆盖。
stack_size/c_stack_size | - | 设置单个协程初始C栈的内存尺寸，默认为2M
log_level | v4.0.0 | 日志等级 [详见](/consts?id=日志等级)
trace_flags | v4.0.0 | 跟踪标签 [详见](/consts?id=跟踪标签)
socket_connect_timeout | v4.2.10 | 建立连接超时时间，**参考[客户端超时规则](/coroutine_client/init?id=超时规则)**
socket_read_timeout | v4.3.0 | 读超时，**参考[客户端超时规则](/coroutine_client/init?id=超时规则)**
socket_write_timeout | v4.3.0 | 写超时，**参考[客户端超时规则](/coroutine_client/init?id=超时规则)**
socket_dns_timeout | v4.4.0 | 域名解析超时，**参考[客户端超时规则](/coroutine_client/init?id=超时规则)**
socket_timeout | v4.2.10 | 发送/接收超时，**参考[客户端超时规则](/coroutine_client/init?id=超时规则)**
dns_cache_expire | v4.2.11 | 设置swoole dns缓存失效时间,单位秒,默认60秒
dns_cache_capacity | v4.2.11 | 设置swoole dns缓存容量,默认1000
hook_flags | v4.4.0 | 一键协程化的hook范围配置，参考[一键协程化](/runtime)
enable_preemptive_scheduler | v4.4.0 | 设置打开协程抢占式调度，协程最大执行时间为10ms，会覆盖[ini配置](/other/config)
dns_server | v4.5.0 | 设置dns查询的server，默认"8.8.8.8"
exit_condition | v4.5.0 | 传入一个`callable`，返回bool，可自定义reactor退出的条件。如: 我希望协程数量等于0时程序才退出, 则可写`Co::set(['exit_condition' => function () {return Co::stats()['coroutine_num'] === 0;}]);`
enable_deadlock_check | v4.6.0 | 设置是否开启协程死锁检测，默认开启
deadlock_check_disable_trace | v4.6.0 | 设置是否输出协程死锁检测的堆栈帧
deadlock_check_limit | v4.6.0 | 限制协程死锁检测时最大输出数
deadlock_check_depth | v4.6.0 | 限制协程死锁检测时返回堆栈帧的数量
max_concurrency | v4.8.2 | 最大并发请求数量

### getOptions()

获取设置的协程相关选项。

!> Swoole版本 >= `v4.6.0` 可用

```php
Swoole\Coroutine::getOptions(): null|array;
```

### create()

创建一个新的协程，并立即执行。

```php
Swoole\Coroutine::create(callable $function, ...$args): int|false
go(callable $function, ...$args): int|false // 参考php.ini的use_shortname配置
```

* **参数**

    * **`callable $function`**
      * **功能**：协程执行的代码，必须为`callable`，系统能创建的协程总数量受限于[server->max_coroutine](/server/setting?id=max_coroutine)设置
      * **默认值**：无
      * **其它值**：无

* **返回值**

    * 创建失败返回`false`
    * 创建成功返回协程的`ID`

!> 由于底层会优先执行子协程的代码，因此只有子协程挂起时，`Coroutine::create`才会返回，继续执行当前协程的代码。

  * **执行顺序**

    在一个协程中使用`go`嵌套创建新的协程。因为Swoole的协程是单进程单线程模型，因此：

    * 使用`go`创建的子协程会优先执行，子协程执行完毕或挂起时，将重新回到父协程向下执行代码
    * 如果子协程挂起后，父协程退出，不影响子协程的执行

    ```php
    \Co\run(function() {
        go(function () {
            Co::sleep(3.0);
            go(function () {
                Co::sleep(2.0);
                echo "co[3] end\n";
            });
            echo "co[2] end\n";
        });

        Co::sleep(1.0);
        echo "co[1] end\n";
    });
    ```

* **协程开销**

  每个协程都是相互独立的，需要创建单独的内存空间(栈内存)，在`PHP-7.2`版本中底层会分配`8K`的`stack`来存储协程的变量，`zval`的尺寸为`16字节`，因此`8K`的`stack`最大可以保存`512`个变量。协程栈内存占用超过`8K`后`ZendVM`会自动扩容。

  协程退出时会释放申请的`stack`内存。

  * `PHP-7.1`、`PHP-7.0`默认会分配`256K`栈内存
  * 可调用`Co::set(['stack_size' => 4096])`修改默认的栈内存尺寸


### defer()

`defer`用于资源的释放, 会在**协程关闭之前**(即协程函数执行完毕时)进行调用, 就算抛出了异常, 已注册的`defer`也会被执行。

!> Swoole版本 >= 4.2.9

```php
Swoole\Coroutine::defer(callable $function);
defer(callable $function); // 短名API
```

!> 需要注意的是, 它的调用顺序是逆序的（先进后出）, 也就是先注册`defer`的后执行, 先进后出. 逆序符合资源释放的正确逻辑, 后申请的资源可能是基于先申请的资源的, 如先释放先申请的资源, 后申请的资源可能就难以释放。

  * **示例**

```php
go(function () {
    defer(function () use ($db) {
        $db->close();
    });
});
```

### exists()

判断指定协程是否存在。

```php
Swoole\Coroutine::exists(int $cid = 0): bool
```

!> Swoole版本 >= v4.3.0

  * **示例**

```php
\Co\run(function () {
    go(function () {
        go(function () {
            Co::sleep(0.001);
            var_dump(Co::exists(Co::getPcid())); // 1: true
        });
        go(function () {
            Co::sleep(0.003);
            var_dump(Co::exists(Co::getPcid())); // 3: false
        });
        Co::sleep(0.002);
        var_dump(Co::exists(Co::getPcid())); // 2: false
    });
});
```

### getCid()

获取当前协程的唯一`ID`, 它的别名为`getuid`, 是一个进程内唯一的正整数。

```php
Swoole\Coroutine::getCid(): int
```

* **返回值**

    * 成功时返回当前协程 `ID`
    * 如果当前不在协程环境中，则返回`-1`

### getPcid()

获取当前协程的父`ID`。

```php
Swoole\Coroutine::getPcid([$cid]): int
```

!> Swoole版本 >= v4.3.0

* **参数**

    * **`int $cid`**
      * **功能**：协程 cid，参数缺省, 可传入某个协程的`id`以获取它的父`id`
      * **默认值**：当前协程
      * **其它值**：无

  * **示例**

```php
var_dump(Co::getPcid());
\Co\run(function () {
    var_dump(Co::getPcid());
    go(function () {
        var_dump(Co::getPcid());
        go(function () {
            var_dump(Co::getPcid());
            go(function () {
                var_dump(Co::getPcid());
            });
            go(function () {
                var_dump(Co::getPcid());
            });
            go(function () {
                var_dump(Co::getPcid());
            });
        });
        var_dump(Co::getPcid());
    });
    var_dump(Co::getPcid());
});
var_dump(Co::getPcid());

// --EXPECT--

// bool(false)
// int(-1)
// int(1)
// int(2)
// int(3)
// int(3)
// int(3)
// int(1)
// int(-1)
// bool(false)
```

!> 非嵌套协程调用`getPcid`将返回`-1` (从非协程空间创建的)  
在非协程内调用`getPcid`将返回`false` (没有父协程)  
`0`作为保留`id`, 不会出现在返回值中

!> 协程之间并没有实质上的持续父子关系, 协程之间是相互隔离, 独立运作的，此`Pcid`可理解为创建了当前协程的协程`id`

  * **用途**

    * **串联多个协程调用栈**

```php
\Co\run(function () {
    go(function () {
        $ptrace = Co::getBackTrace(Co::getPcid());
        // balababala
        var_dump(array_merge($ptrace, Co::getBackTrace(Co::getCid())));
    });
});
```

### getContext()

获取当前协程的上下文对象。

```php
Swoole\Coroutine::getContext([int $cid = 0]): Swoole\Coroutine\Context
```

!> Swoole版本 >= v4.3.0

* **参数**

    * **`int $cid`**
      * **功能**：协程 `CID`，可选参数
      * **默认值**：当前协程 `CID`
      * **其它值**：无

  * **作用**

    * 协程退出后上下文自动清理 (如无其它协程或全局变量引用)
    * 无`defer`注册和调用的开销 (无需注册清理方法, 无需调用函数清理)
    * 无PHP数组实现的上下文的哈希计算开销 (在协程数量巨大时有一定好处)
    * `Co\Context`使用`ArrayObject`, 满足各种存储需求 (既是对象, 也可以以数组方式操作)

  * **示例**

```php
function func(callable $fn, ...$args)
{
    go(function () use ($fn, $args) {
        $fn(...$args);
        echo 'Coroutine#' . Co::getCid() . ' exit' . PHP_EOL;
    });
}

/**
* Compatibility for lower version
* @param object|Resource $object
* @return int
*/
function php_object_id($object)
{
    static $id = 0;
    static $map = [];
    $hash = spl_object_hash($object);
    return $map[$hash] ?? ($map[$hash] = ++$id);
}

class Resource
{
    public function __construct()
    {
        echo __CLASS__ . '#' . php_object_id((object)$this) . ' constructed' . PHP_EOL;
    }

    public function __destruct()
    {
        echo __CLASS__ . '#' . php_object_id((object)$this) . ' destructed' . PHP_EOL;
    }
}

$context = new Co\Context();
assert($context instanceof ArrayObject);
assert(Co::getContext() === null);
func(function () {
    $context = Co::getContext();
    assert($context instanceof Co\Context);
    $context['resource1'] = new Resource;
    $context->resource2 = new Resource;
    func(function () {
        Co::getContext()['resource3'] = new Resource;
        Co::yield();
        Co::getContext()['resource3']->resource4 = new Resource;
        Co::getContext()->resource5 = new Resource;
    });
});
Co::resume(2);

Swoole\Event::wait();

// --EXPECT--
// Resource#1 constructed
// Resource#2 constructed
// Resource#3 constructed
// Coroutine#1 exit
// Resource#2 destructed
// Resource#1 destructed
// Resource#4 constructed
// Resource#5 constructed
// Coroutine#2 exit
// Resource#5 destructed
// Resource#3 destructed
// Resource#4 destructed
```

### yield()

手动让出当前协程的执行权。而不是基于IO的[协程调度](/coroutine?id=协程调度)

此方法拥有另外一个别名：`Coroutine::suspend()`

!> 必须与`Coroutine::resume()`方法成对使用。该协程`yield`以后，必须由其他外部协程`resume`，否则将会造成协程泄漏，被挂起的协程永远不会执行。

```php
Swoole\Coroutine::yield();
```

  * **示例**

```php
$cid = go(function () {
    echo "co 1 start\n";
    Co::yield();
    echo "co 1 end\n";
});

go(function () use ($cid) {
    echo "co 2 start\n";
    Co::sleep(0.5);
    Co::resume($cid);
    echo "co 2 end\n";
});
Swoole\Event::wait();
```

### resume()

手动恢复某个协程，使其继续运行，不是基于IO的[协程调度](/coroutine?id=协程调度)。

!> 当前协程处于挂起状态时，另外的协程中可以使用`resume`再次唤醒当前协程

```php
Swoole\Coroutine::resume(int $coroutineId);
```

* **参数**

    * **`int $coroutineId`**
      * **功能**：要恢复的协程`ID`
      * **默认值**：无
      * **其它值**：无

  * **示例**

```php
$id = go(function(){
    $id = Co::getuid();
    echo "start coro $id\n";
    Co::suspend();
    echo "resume coro $id @1\n";
    Co::suspend();
    echo "resume coro $id @2\n";
});
echo "start to resume $id @1\n";
Co::resume($id);
echo "start to resume $id @2\n";
Co::resume($id);
echo "main\n";
Swoole\Event::wait();

// --EXPECT--
// start coro 1
// start to resume 1 @1
// resume coro 1 @1
// start to resume 1 @2
// resume coro 1 @2
// main
```

### list()

遍历当前进程内的所有协程。

```php
Swoole\Coroutine::list(): Swoole\Coroutine\Iterator
Swoole\Coroutine::listCoroutines(): Swoole\Coroitine\Iterator
```

!> `v4.3.0`以下版本需使用`listCoroutines`, 新版本缩略了该方法的名称并将`listCoroutines`设为别名。`list`在`v4.1.0`或更高版本可用。

* **返回值**

    * 返回迭代器，可使用`foreach`遍历，或使用`iterator_to_array`转为数组

```php
$coros = Swoole\Coroutine::listCoroutines();
foreach($coros as $cid)
{
    var_dump(Swoole\Coroutine::getBackTrace($cid));
}
```

### stats()

获取协程状态。

```php
Swoole\Coroutine::stats(): array
```

* **返回值**

key | 作用
---|---
event_num | 当前reactor事件数量
signal_listener_num | 当前监听信号的数量
aio_task_num | 异步IO任务数量 (这里的aio指文件IO或dns, 不包含其它网络IO, 下同)
aio_worker_num | 异步IO工作线程数量
c_stack_size | 每个协程的C栈大小
coroutine_num | 当前运行的协程数量
coroutine_peak_num | 当前运行的协程数量的峰值
coroutine_last_cid | 最后创建协程的id

  * **示例**

```php
var_dump(Swoole\Coroutine::stats());

array(1) {
  ["c_stack_size"]=>
  int(2097152)
  ["coroutine_num"]=>
  int(132)
  ["coroutine_peak_num"]=>
  int(2)
}
```

### getBackTrace()

获取协程函数调用栈。

```php
Swoole\Coroutine::getBackTrace(int $cid = 0, int $options = DEBUG_BACKTRACE_PROVIDE_OBJECT, int $limit = 0): array
```

!> Swoole版本 >= v4.1.0

* **参数**

    * **`int $cid`**
      * **功能**：协程的 `CID`
      * **默认值**：当前协程 `CID`
      * **其它值**：无

    * **`int $options`**
      * **功能**：设置选项
      * **默认值**：`DEBUG_BACKTRACE_PROVIDE_OBJECT` 【是否填充`object`的索引】
      * **其它值**：`DEBUG_BACKTRACE_IGNORE_ARGS` 【是否忽略args的索引，包括所有的 function/method 的参数，能够节省内存开销】

    * **`int limit`**
      * **功能**：限制返回堆栈帧的数量
      * **默认值**：`0`
      * **其它值**：无

* **返回值**

    * 指定的协程不存在，将返回`false`
    * 成功返回数组，格式与 [debug_backtrace](https://www.php.net/manual/zh/function.debug-backtrace.php) 函数返回值相同

  * **示例**

```php
function test1() {
    test2();
}

function test2() {
    while(true) {
        Co::sleep(10);
        echo __FUNCTION__." \n";
    }
}
\Co\run(function () {
    $cid = go(function () {
        test1();
    });

    go(function () use ($cid) {
        while(true) {
            echo "BackTrace[$cid]:\n-----------------------------------------------\n";
            //返回数组，需要自行格式化输出
            var_dump(Co::getBackTrace($cid))."\n";
            Co::sleep(3);
        }
    });
});
Swoole\Event::wait();
```

### printBackTrace()

打印协程函数调用栈。参数和`getBackTrace`一致。

!> Swoole版本 >= `v4.6.0` 可用

```php
Swoole\Coroutine::printBackTrace(int $cid = 0, int $options = DEBUG_BACKTRACE_PROVIDE_OBJECT, int $limit = 0);
```

### getElapsed()

获取协程运行的时间以便于分析统计或找出僵尸协程

!> Swoole版本 >= `v4.5.0` 可用

```php
Swoole\Coroutine::getElapsed([$cid]): int
```
* **参数**

    * **`int $cid`**
      * **功能**：可选参数，协程的 `CID`
      * **默认值**：当前协程 `CID`
      * **其它值**：无

* **返回值**

    * 协程已运行的时间浮点数, 毫秒级精度

### cancel()

用于取消某个协程，但不能对当前协程发起取消操作

!> Swoole版本 >= `v4.7.0` 可用

```php
Swoole\Coroutine::cancel($cid): bool
```
* **参数**

    * **`int $cid`**
        * **功能**：协程的 `CID`
        * **默认值**：无
        * **其它值**：无

* **返回值**

    * 成功时返回 `true`，失败将会返回 `false`
    * 取消失败可以调用 [swoole_last_error()](/functions?id=swoole_last_error) 查看错误信息

### isCanceled()

用于判断当前操作是否是被手动取消的

!> Swoole版本 >= `v4.7.0` 可用

```php
Swoole\Coroutine::isCanceled(): bool
```

* **返回值**

    * 手动取消正常结束, 将返回`true`, 如失败将返回`false`

#### 示例

```php
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function () {
    $chan = new Coroutine\Channel(1);
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        System::sleep(0.002);
        assert(Coroutine::cancel($cid) === true);
    });

    assert($chan->push("hello world [1]", 100) === true);
    assert(Coroutine::isCanceled() === false);
    assert($chan->errCode === SWOOLE_CHANNEL_OK);

    assert($chan->push("hello world [2]", 100) === false);
    assert(Coroutine::isCanceled() === true);
    assert($chan->errCode === SWOOLE_CHANNEL_CANCELED);

    echo "Done\n";
});
```

### enableScheduler()

临时打开协程抢占式调度。

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Coroutine::enableScheduler();
```

### disableScheduler()

临时关闭协程抢占式调度。

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Coroutine::disableScheduler();
```

### getStackUsage()

获取当前PHP栈的内存使用量。

!> Swoole版本 >= `v4.8.0` 可用

```php
Swoole\Coroutine::getStackUsage([$cid]): int
```

* **参数**

    * **`int $cid`**
        * **功能**：可选参数，协程的 `CID`
        * **默认值**：当前协程 `CID`
        * **其它值**：无

### join()

并发执行多个协程。

!> Swoole版本 >= `v4.8.0` 可用

```php
Swoole\Coroutine::join(array $cid_array, float $timeout = -1): bool
```

* **参数**

    * **`array $cid_array`**
        * **功能**：需要执行协程的 `CID` 数组
        * **默认值**：无
        * **其它值**：无

    * **`float $timeout`**
        * **功能**：总的超时时间，超时后会立即返回。但正在运行的协程会继续执行完毕，而不会中止
        * **默认值**：-1
        * **其它值**：无

* **返回值**

    * 成功时返回 `true`，失败将会返回 `false`
    * 取消失败可以调用 [swoole_last_error()](/functions?id=swoole_last_error) 查看错误信息

* **使用示例**

```php
use Swoole\Coroutine;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

run(function () {
    $status = Coroutine::join([
        go(function () use (&$result) {
            $result['baidu'] = strlen(file_get_contents('https://www.baidu.com/'));
        }),
        go(function () use (&$result) {
            $result['google'] = strlen(file_get_contents('https://www.google.com/'));
        })
    ], 1);
    var_dump($result, $status, swoole_strerror(swoole_last_error(), 9));
});
```

## 函数

### batch()

并发执行多个协程，并且通过数组，返回这些协程方法的返回值。

!> Swoole版本 >= `v4.5.2` 可用

```php
Swoole\Coroutine\batch(array $tasks, float $timeout = -1): array
```

* **参数**

    * **`array $tasks`**
      * **功能**：传入方法回调的数组，如果指定了 `key`，则返回值也会被该 `key` 指向
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：总的超时时间，超时后会立即返回。但正在运行的协程会继续执行完毕，而不会中止
      * **默认值**：-1
      * **其它值**：无

* **返回值**

    * 返回一个数组，里面包含回调的返回值。如果`$tasks`参数中，指定了 `key`，则返回值也会被该 `key` 指向

* **使用示例**

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\batch;

Coroutine::set(['hook_flags' => SWOOLE_HOOK_ALL]);

$start_time = microtime(true);
Coroutine\run(function () {
    $use = microtime(true);
    $results = batch([
        'file_put_contents' => function () {
            return file_put_contents(__DIR__ . '/greeter.txt', "Hello,Swoole.");
        },
        'gethostbyname' => function () {
            return gethostbyname('localhost');
        },
        'file_get_contents' => function () {
            return file_get_contents(__DIR__ . '/greeter.txt');
        },
        'sleep' => function () {
            sleep(1);
            return true; // 返回NULL 因为超过了设置的超时时间0.1秒，超时后会立即返回。但正在运行的协程会继续执行完毕，而不会中止。
        },
        'usleep' => function () {
            usleep(1000);
            return true;
        },
    ], 0.1);
    $use = microtime(true) - $use;
    echo "Use {$use}s, Result:\n";
    var_dump($results);
});
$end_time =  microtime(true) - $start_time;
echo "Use {$end_time}s, Done\n";
```

### parallel()

并发执行多个协程。

!> Swoole版本 >= `v4.5.3` 可用

```php
Swoole\Coroutine\parallel(int $n, callable $fn): void
```

* **参数**

    * **`int $n`**
      * **功能**：设置最大的协程数为`$n`
      * **默认值**：无
      * **其它值**：无

    * **`callable $fn`**
      * **功能**：对应需要执行的回调函数
      * **默认值**：无
      * **其它值**：无

* **使用示例**

```php
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\parallel;

$start_time = microtime(true);
Coroutine\run(function () {
    $use = microtime(true);
    $results = [];
    parallel(2, function () use (&$results) {
        System::sleep(0.2);
        $results[] = System::gethostbyname('localhost');
    });
    $use = microtime(true) - $use;
    echo "Use {$use}s, Result:\n";
    var_dump($results);
});
$end_time =  microtime(true) - $start_time;
echo "Use {$end_time}s, Done\n";
```

### map()

类似于[array_map](https://www.php.net/manual/zh/function.array-map.php)，为数组的每个元素应用回调函数。

!> Swoole版本 >= `v4.5.5` 可用

```php
Swoole\Coroutine\map(array $list, callable $fn, float $timeout = -1): array
```

* **参数**

    * **`array $list`**
      * **功能**：运行`$fn`函数的数组
      * **默认值**：无
      * **其它值**：无

    * **`callable $fn`**
      * **功能**：`$list`数组中的每个元素需要执行的回调函数
      * **默认值**：无
      * **其它值**：无

    * **`float $timeout`**
      * **功能**：总的超时时间，超时后会立即返回。但正在运行的协程会继续执行完毕，而不会中止
      * **默认值**：-1
      * **其它值**：无

* **使用示例**

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\map;

function fatorial(int $n): int
{
    return array_product(range($n, 1));
}

Coroutine\run(function () {
    $results = map([2, 3, 4], 'fatorial'); 
    print_r($results);
});
```

### deadlock_check()

协程死锁检测，调用时会输出相关堆栈信息；

默认**开启**，在 [EventLoop](learn?id=什么是eventloop) 终止后，如果存在协程死锁，底层会自动调用；

可以通过在[Coroutine::set](/coroutine/coroutine?id=set)中设置`enable_deadlock_check`进行关闭。

!> Swoole版本 >= `v4.6.0` 可用

```php
Swoole\Coroutine\deadlock_check();
```
