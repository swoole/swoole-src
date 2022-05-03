# 进程间无锁计数器 Atomic

`Atomic`是`Swoole`底层提供的原子计数操作类，可以方便整数的无锁原子增减。

* 使用共享内存，可以在不同的进程之间操作计数
* 基于`gcc/clang`提供的`CPU`原子指令，无需加锁
* 在服务器程序中必须在`Server->start`前创建才能在`Worker`进程中使用
* 默认使用`32`位无符号类型，如需要`64`有符号整型，可使用`Swoole\Atomic\Long`

!> 请勿在[onReceive](/server/events?id=onreceive)等回调函数中创建计数器，否则内存会持续增长，造成内存泄漏。

!> 支持`64`位有符号长整型原子计数，需要使用`new Swoole\Atomic\Long`来创建。`Atomic\Long` 不支持`wait`和`wakeup`方法。

## 完整示例

```php
$atomic = new Swoole\Atomic();

$serv = new Swoole\Server('127.0.0.1', '9501');
$serv->set([
    'worker_num' => 1,
    'log_file' => '/dev/null'
]);
$serv->on("start", function ($serv) use ($atomic) {
    if ($atomic->add() == 2) {
        $serv->shutdown();
    }
});
$serv->on("ManagerStart", function ($serv) use ($atomic) {
    if ($atomic->add() == 2) {
        $serv->shutdown();
    }
});
$serv->on("ManagerStop", function ($serv) {
    echo "shutdown\n";
});
$serv->on("Receive", function () {
    
});
$serv->start();
```

## 方法

### __construct()

构造函数。创建一个原子计数对象。

```php
Swoole\Atomic::__construct(int $init_value = 0);
```

  * **参数** 

    * **`int $init_value`**
      * **功能**：指定初始化的数值
      * **默认值**：`0`
      * **其它值**：无

!> -`Atomic`只能操作`32`位无符号整数，最大支持`42`亿，不支持负数；  
-在`Server`中使用原子计数器，必须在`Server->start`前创建；  
-在[Process](/process/process)中使用原子计数器，必须在`Process->start`前创建。

### add()

增加计数。

```php
Swoole\Atomic->add(int $add_value = 1): int
```

  * **参数** 

    * **`int $add_value`**
      * **功能**：要增加的数值【必须为正整数】
      * **默认值**：`1`
      * **其它值**：无

  * **返回值**

    * `add`方法操作成功后返回结果数值

!> 与原值相加如果超过`42`亿，将会溢出，高位数值会被丢弃。

### sub()

减少计数。

```php
Swoole\Atomic->sub(int $sub_value = 1): int
```

  * **参数** 

    * **`int $sub_value`**
      * **功能**：要减少的数值【必须为正整数】
      * **默认值**：`1`
      * **其它值**：无

  * **返回值**

    * `sub`方法操作成功后返回结果数值

!> 与原值相减如果低于0将会溢出，高位数值会被丢弃。

### get()

获取当前计数的值。

```php
Swoole\Atomic->get(): int
```

  * **返回值**

    * 返回当前的数值

### set()

将当前值设置为指定的数字。

```php
Swoole\Atomic->set(int $value): void
```

  * **参数** 

    * **`int $value`**
      * **功能**：指定要设置的目标数值
      * **默认值**：无
      * **其它值**：无

### cmpset()

如果当前数值等于参数`1`，则将当前数值设置为参数`2`。   

```php
Swoole\Atomic->cmpset(int $cmp_value, int $set_value): bool
```

  * **参数** 

    * **`int $cmp_value`**
      * **功能**：如果当前数值等于`$cmp_value`返回`true`，并将当前数值设置为`$set_value`，如果不等于返回`false`【必须为小于`42`亿的整数】
      * **默认值**：无
      * **其它值**：无

    * **`int $set_value`**
      * **功能**：如果当前数值等于`$cmp_value`返回`true`，并将当前数值设置为`$set_value`，如果不等于返回`false`【必须为小于`42`亿的整数】
      * **默认值**：无
      * **其它值**：无

### wait()

设置为wait状态。

!> 当原子计数的值为0时程序进入等待状态。另外一个进程调用`wakeup`可以再次唤醒程序。底层基于`Linux Futex`实现，使用此特性，可以仅用`4`字节内存实现一个等待、通知、锁的功能。在不支持`Futex`的平台下，底层会使用循环`usleep(1000)`模拟实现。

```php
Swoole\Atomic->wait(float $timeout = 1.0): bool
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：指定超时时间【设置为`-1`时表示永不超时，会持续等待直到有其他进程唤醒】
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`1`
      * **其它值**：无

  * **返回值** 

    * 超时返回`false`，错误码为`EAGAIN`，可使用`swoole_errno`函数获取
    * 成功返回`true`，表示有其他进程通过`wakeup`成功唤醒了当前的锁

  * **协程环境**

  `wait`会阻塞整个进程而不是协程，因此请勿在协程环境中使用`Atomic->wait()`避免引起进程挂起。

!> -使用`wait/wakeup`特性时，原子计数的值只能为`0`或`1`，否则会导致无法正常使用；  
-当然原子计数的值为`1`时，表示不需要进入等待状态，资源当前就是可用。`wait`函数会立即返回`true`。

  * **使用示例**

    ```php
    $n = new Swoole\Atomic;
    if (pcntl_fork() > 0) {
        echo "master start\n";
        $n->wait(1.5);
        echo "master end\n";
    } else {
        echo "child start\n";
        sleep(1);
        $n->wakeup();
        echo "child end\n";
    }
    ```

### wakeup()

唤醒处于wait状态的其他进程。

```php
Swoole\Atomic->wakeup(int $n = 1): bool
```

  * **参数** 

    * **`int $n`**
      * **功能**：唤醒的进程数量
      * **默认值**：无
      * **其它值**：无

* 当前原子计数如果为`0`时，表示没有进程正在`wait`，`wakeup`会立即返回`true`；
* 当前原子计数如果为`1`时，表示当前有进程正在`wait`，`wakeup`会唤醒等待的进程，并返回`true`；
* 被唤醒的进程返回后，会将原子计数设置为`0`，这时可以再次调用`wakeup`唤醒其他正在`wait`的进程。
