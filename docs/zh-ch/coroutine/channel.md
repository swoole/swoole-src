# Coroutine\Channel

> 建议先查看[概览](/coroutine)，了解一些协程基本概念后再看此节。

通道，用于协程间通讯，支持多生产者协程和多消费者协程。底层自动实现了协程的切换和调度。

## 实现原理

  * 通道与`PHP`的`Array`类似，仅占用内存，没有其他额外的资源申请，所有操作均为内存操作，无`IO`消耗
  * 底层使用`PHP`引用计数实现，无内存拷贝。即使是传递巨大字符串或数组也不会产生额外性能消耗
  * `channel`基于引用计数实现，是零拷贝的

## 使用示例

```php
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;

run(function(){
    $channel = new Channel(1);
    Coroutine::create(function () use ($channel) {
        for($i = 0; $i < 10; $i++) {
            Coroutine::sleep(1.0);
            $channel->push(['rand' => rand(1000, 9999), 'index' => $i]);
            echo "{$i}\n";
        }
    });
    Coroutine::create(function () use ($channel) {
        while(1) {
            $data = $channel->pop(2.0);
            if ($data) {
                var_dump($data);
            } else {
                assert($channel->errCode === SWOOLE_CHANNEL_TIMEOUT);
                break;
            }
        }
    });
});
```

## 方法

### __construct()

通道构造方法。

```php
Swoole\Coroutine\Channel::__construct(int $capacity = 1)
```

  * **参数** 

    * **`int $capacity`**
      * **功能**：设置容量 【必须为大于或等于`1`的整数】
      * **默认值**：`1`
      * **其它值**：无

!> 底层使用PHP引用计数来保存变量，缓存区只需要占用 `$capacity * sizeof(zval)` 字节的内存，`PHP7`版本下`zval`为`16`字节，如`$capacity = 1024`时，`Channel`最大将占用`16K`内存

!> 在`Server`中使用时必须在[onWorkerStart](/server/events?id=onworkerstart)之后创建

### push()

向通道中写入数据。

```php
Swoole\Coroutine\Channel->push(mixed $data, float $timeout = -1): bool
```

  * **参数** 

    * **`mixed $data`**
      * **功能**：push 数据 【可以是任意类型的PHP变量，包括匿名函数和资源】
      * **默认值**：无
      * **其它值**：无

      !> 为避免产生歧义，请勿向通道中写入空数据，如`0`、`false`、`空字符串`、`null`

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`-1`
      * **其它值**：无
      * **版本影响**：Swoole版本 >= v4.2.12

      !> 在通道已满的情况下，`push`会挂起当前协程，在约定的时间内，如果没有任何消费者消费数据，将发生超时，底层会恢复当前协程，`push`调用立即返回`false`，写入失败

  * **返回值**

    * 执行成功返回`true`
    * 通道被关闭时，执行失败返回`false`，可使用`$channel->errCode`得到错误码

  * **扩展**

    * **通道已满**

      * 自动`yield`当前协程，其他消费者协程`pop`消费数据后，通道可写，将重新`resume`当前协程
      * 多个生产者协程同时`push`时，底层自动进行排队，底层会按照顺序逐个`resume`这些生产者协程

    * **通道为空**

      * 自动唤醒其中一个消费者协程
      * 多个消费者协程同时`pop`时，底层自动进行排队，按照顺序逐个`resume`这些消费者协程

!> `Coroutine\Channel`使用本地内存，不同的进程之间内存是隔离的。只能在同一进程的不同协程内进行`push`和`pop`操作 

### pop()

从通道中读取数据。

```php
Swoole\Coroutine\Channel->pop(float $timeout = -1): mixed
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：设置超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`-1`【表示永不超时】
      * **其它值**：无
      * **版本影响**：Swoole版本 >= v4.0.3

  * **返回值**

    * 返回值可以是任意类型的PHP变量，包括匿名函数和资源
    * 通道被关闭时，执行失败返回`false`

  * **扩展**

    * **通道已满**

      * `pop`消费数据后，将自动唤醒其中一个生产者协程，让其写入新数据
      * 多个生产者协程同时`push`时，底层自动进行排队，按照顺序逐个`resume`这些生产者协程

    * **通道为空**

      * 自动`yield`当前协程，其他生产者协程`push`生产数据后，通道可读，将重新`resume`当前协程
      * 多个消费者协程同时`pop`时，底层自动进行排队，底层会按照顺序逐个`resume`这些消费者协程

### stats()

获取通道的状态。

```php
Swoole\Coroutine\Channel->stats(): array
```

  * **返回值**

    返回一个数组，缓冲通道将包括`4`项信息，无缓冲通道返回`2`项信息
    
    - `consumer_num` 消费者数量，表示当前通道为空，有`N`个协程正在等待其他协程调用`push`方法生产数据
    - `producer_num` 生产者数量，表示当前通道已满，有`N`个协程正在等待其他协程调用`pop`方法消费数据
    - `queue_num` 通道中的元素数量

```php
array(
  "consumer_num" => 0,
  "producer_num" => 1,
  "queue_num" => 10
);
```

### close()

关闭通道。并唤醒所有等待读写的协程。

```php
Swoole\Coroutine\Channel->close(): bool
```

!> 唤醒所有生产者协程，`push`方法返回`false`；唤醒所有消费者协程，`pop`方法返回`false`

### length()

获取通道中的元素数量。

```php
Swoole\Coroutine\Channel->length(): int
```

### isEmpty()

判断当前通道是否为空。

```php
Swoole\Coroutine\Channel->isEmpty(): bool
```

### isFull()

判断当前通道是否已满。

```php
Swoole\Coroutine\Channel->isFull(): bool
```

## 属性

### capacity

通道缓冲区容量。

[构造函数](/coroutine/channel?id=__construct)中设定的容量会保存在此，不过**如果设定的容量小于1**则此变量会等于1

```php
Swoole\Coroutine\Channel->capacity: int
```

### errCode

获取错误码。

```php
Swoole\Coroutine\Channel->errCode: int
```

  * **返回值**

值 | 对应常量 | 作用
---|---|---
0 | SWOOLE_CHANNEL_OK | 默认 成功
-1 | SWOOLE_CHANNEL_TIMEOUT | 超时 pop失败时(超时)
-2 | SWOOLE_CHANNEL_CLOSED | channel已关闭，继续操作channel
