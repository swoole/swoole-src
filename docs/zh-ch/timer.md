# 定时器 Timer

毫秒精度的定时器。底层基于`epoll_wait`和`setitimer`实现，数据结构使用`最小堆`，可支持添加大量定时器。

* 在同步IO进程中使用`setitimer`和信号实现，如`Manager`和`TaskWorker`进程
* 在异步IO进程中使用`epoll_wait`/`kevent`/`poll`/`select`超时时间实现

## 性能

底层使用最小堆数据结构实现定时器，定时器的添加和删除，全部为内存操作，因此性能是非常高的。

> 官方的基准测试脚本 [timer.php](https://github.com/swoole/benchmark/blob/master/timer.php) 中，添加或删除`10`万个随机时间的定时器耗时为`0.08s`左右。

```shell
~/workspace/swoole/benchmark$ php timer.php
add 100000 timer :0.091133117675781s
del 100000 timer :0.084658145904541s
```

!> 定时器是内存操作，无`IO`消耗

## 差异

`Timer`与`PHP`本身的`pcntl_alarm`是不同的。`pcntl_alarm`是基于`时钟信号 + tick`函数实现存在一些缺陷：

  * 最大仅支持到秒，而`Timer`可以到毫秒级别
  * 不支持同时设定多个定时器程序
  * `pcntl_alarm`依赖`declare(ticks = 1)`，性能很差

## 零毫秒定时器

底层不支持时间参数为`0`的定时器。这与`Node.js`等编程语言不同。在`Swoole`里可以使用[Swoole\Event::defer](/event?id=defer)实现类似的功能。

```php
Swoole\Event::defer(function () {
  echo "hello\n";
});
```

!> 上述代码与`JS`中的`setTimeout(func, 0)`效果是完全一致的。

## 别名

`tick()`、`after()`、`clear()`都拥有一个函数风格的别名

类静态方法 | 函数风格别名
---|---
`Swoole\Timer::tick()` | `swoole_timer_tick()`
`Swoole\Timer::after()` | `swoole_timer_after()`
`Swoole\Timer::clear()` | `swoole_timer_clear()`

## 方法

### tick()

设置一个间隔时钟定时器。

与`after`定时器不同的是`tick`定时器会持续触发，直到调用 [Timer::clear](/timer?id=clear) 清除。

```php
Swoole\Timer::tick(int $msec, callable $callback_function, ...$params): int
```

!> 1. 定时器仅在当前进程空间内有效  
   2. 定时器是纯异步实现的，不能与[同步IO](/learn?id=同步io异步io)的函数一起使用，否则定时器的执行时间会发生错乱  
   3. 定时器在执行的过程中可能存在一定误差

  * **参数** 

    * **`int $msec`**
      * **功能**：指定时间
      * **值单位**：毫秒【如`1000`表示`1`秒，`v4.2.10`以下版本最大不得超过 `86400000`】
      * **默认值**：无
      * **其它值**：无

    * **`callable $callback_function`**
      * **功能**：时间到期后所执行的函数，必须是可以调用的
      * **默认值**：无
      * **其它值**：无

    * **`...$params`**
      * **功能**：给执行函数传递数据【此参数也为可选参数】
      * **默认值**：无
      * **其它值**：无
      
      !> 可以使用匿名函数的`use`语法传递参数到回调函数中

  * **$callback_function 回调函数** 

    ```php
    callbackFunction(int $timer_id, ...$params);
    ```

      * **`int $timer_id`**
        * **功能**：定时器的`ID`【可用于[Timer::clear](/timer?id=clear)清除此定时器】
        * **默认值**：无
        * **其它值**：无

      * **`...$params`**
        * **功能**：由`Timer::tick`传入的第三个参数`$param`
        * **默认值**：无
        * **其它值**：无

  * **扩展**

    * **定时器校正**

      定时器回调函数的执行时间不影响下一次定时器执行的时间。实例：在`0.002s`设置了`10ms`的`tick`定时器，第一次会在`0.012s`执行回调函数，如果回调函数执行了`5ms`，下一次定时器仍然会在`0.022s`时触发，而不是`0.027s`。
      
      但如果定时器回调函数的执行时间过长，甚至覆盖了下一次定时器执行的时间。底层会进行时间校正，丢弃已过期的行为，在下一时间回调。如上面例子中`0.012s`时的回调函数执行了`15ms`，本该在`0.022s`产生一次定时回调。实际上本次定时器在`0.027s`才返回，这时定时早已过期。底层会在`0.032s`时再次触发定时器回调。
    
    * **协程模式**

      在协程环境下`Timer::tick`回调中会自动创建一个协程，可以直接使用协程相关`API`，无需调用`go`创建协程。
      
      !> 可设置 [enable_coroutine](/timer?id=close-timer-co) 关闭自动创建协程

  * **使用示例**

    ```php
    Swoole\Timer::tick(1000, function(){
        echo "timeout\n";
    });
    ```

    * **正确示例**

    ```php
    Swoole\Timer::tick(3000, function (int $timer_id, $param1, $param2) {
        echo "timer_id #$timer_id, after 3000ms.\n";
        echo "param1 is $param1, param2 is $param2.\n";

        Swoole\Timer::tick(14000, function ($timer_id) {
            echo "timer_id #$timer_id, after 14000ms.\n";
        });
    }, "A", "B");
    ```

    * **错误示例**

    ```php
    Swoole\Timer::tick(3000, function () {
        echo "after 3000ms.\n";
        sleep(14);
        echo "after 14000ms.\n";
    });
    ```

### after()

在指定的时间后执行函数。`Swoole\Timer::after`函数是一个一次性定时器，执行完成后就会销毁。

此函数与`PHP`标准库提供的`sleep`函数不同，`after`是非阻塞的。而`sleep`调用后会导致当前的进程进入阻塞，将无法处理新的请求。

```php
Swoole\Timer::after(int $msec, callable $callback_function, ...$params): int
```

  * **参数** 

    * **`int $msec`**
      * **功能**：指定时间
      * **值单位**：毫秒【如`1000`表示`1`秒，`v4.2.10`以下版本最大不得超过 `86400000`】
      * **默认值**：无
      * **其它值**：无

    * **`callable $callback_function`**
      * **功能**：时间到期后所执行的函数，必须是可以调用的。
      * **默认值**：无
      * **其它值**：无

    * **`...$params`**
      * **功能**：给执行函数传递数据【此参数也为可选参数】
      * **默认值**：无
      * **其它值**：无
      
      !> 可以使用匿名函数的use语法传递参数到回调函数中

  * **返回值**

    * 执行成功返回定时器`ID`，若取消定时器，可调用 [Swoole\Timer::clear](/timer?id=clear)

  * **扩展**

    * **协程模式**

      在协程环境下[Swoole\Timer::after](/timer?id=after)回调中会自动创建一个协程，可以直接使用协程相关`API`，无需调用`go`创建协程。
      
      !> 可设置 [enable_coroutine](/timer?id=close-timer-co) 关闭自动创建协程

  * **使用示例**

```php
$str = "Swoole";
Swoole\Timer::after(1000, function() use ($str) {
    echo "Hello, $str\n";
});
```

### clear()

使用定时器`ID`来删除定时器。

```php
Swoole\Timer::clear(int $timer_id): bool
```

  * **参数** 

    * **`int $timer_id`**
      * **功能**：定时器`ID`【调用[Timer::tick](/timer?id=tick)、[Timer::after](/timer?id=after)后会返回一个整数的ID】
      * **默认值**：无
      * **其它值**：无

!> `Swoole\Timer::clear`不能用于清除其他进程的定时器，只作用于当前进程

  * **使用示例**

```php
$timer = Swoole\Timer::after(1000, function () {
    echo "timeout\n";
});

var_dump(Swoole\Timer::clear($timer));
var_dump($timer);

// 输出：bool(true) int(1)
// 不输出：timeout
```

### clearAll()

清除当前 Worker 进程内的所有定时器。

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Timer::clearAll(): bool
```

### info()

返回`timer`的信息。

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Timer::info(int $timer_id): array
```

  * **返回值**

```php
array(5) {
  ["exec_msec"]=>
  int(6000)
  ["exec_count"]=> // v4.8.0 添加
  int(5)
  ["interval"]=>
  int(1000)
  ["round"]=>
  int(0)
  ["removed"]=>
  bool(false)
}
```

### list()

返回定时器迭代器, 可使用`foreach`遍历当前 Worker 进程内所有`timer`的 id

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Timer::list(): Swoole\Timer\Iterator
```

  * **使用示例**

```php
foreach (Swoole\Timer::list() as $timer_id) {
    var_dump(Swoole\Timer::info($timer_id));
}
```

### stats()

查看定时器状态。

!> Swoole版本 >= `v4.4.0` 可用

```php
Swoole\Timer::stats(): array
```

  * **返回值**

```php
array(3) {
  ["initialized"]=>
  bool(true)
  ["num"]=>
  int(1000)
  ["round"]=>
  int(1)
}
```

### set()

设置定时器相关参数。

```php
Swoole\Timer::set(array $array): void
```

!> 此方法从 `v4.6.0` 版本标记为废弃。

## 关闭协程 :id=close-timer-co

默认定时器在执行回调函数时会自动创建协程，可单独设置定时器关闭协程。

```php
swoole_async_set([
  'enable_coroutine' => false,
]);
```
