# Process\Manager

进程管理器，基于[Process\Pool](/process/process_pool)实现。可以管理多个进程。相比与`Process\Pool`，可以非常方便的创建多个执行不同任务的进程，并且可以控制每一个进程是否要处于协程环境。

## 版本支持情况

| 版本号 | 类名                          | 更新说明                                 |
| ------ | ----------------------------- | ---------------------------------------- |
| v4.5.3 | Swoole\Process\ProcessManager | -                                        |
| v4.5.5 | Swoole\Process\Manager        | 重命名，ProcessManager 为 Manager 的别名 |

!> 在`v4.5.3`以上的版本可用。

## 使用示例

```php
use Swoole\Process\Manager;
use Swoole\Process\Pool;

$pm = new Manager();

for ($i = 0; $i < 2; $i++) {
    $pm->add(function (Pool $pool, int $workerId) {
    });
}

$pm->start();
```

## 方法

### __construct()

构造方法。

```php
Swoole\Process\Manager::__construct(int $ipcType = SWOOLE_IPC_NONE, int $msgQueueKey = 0);
```

* **参数**

  * **`int $ipcType`**
    * **功能**：进程间通信的模式，和`Process\Pool`的`$ipc_type`一致【默认为`0`表示不使用任何进程间通信特性】
    * **默认值**：`0`
    * **其它值**：无

  * **`int $msgQueueKey`**
    * **功能**：消息队列的 `key`，和`Process\Pool`的`$msgqueue_key`一致
    * **默认值**：无
    * **其它值**：无

### setIPCType()

设置工作进程之间的通信方式。

```php
Swoole\Process\Manager->setIPCType(int $ipcType): self;
```

* **参数**

  * **`int $ipcType`**
    * **功能**：进程间通信的模式
    * **默认值**：无
    * **其它值**：无

### getIPCType()

获取工作进程之间的通信方式。

```php
Swoole\Process\Manager->getIPCType(): int;
```

### setMsgQueueKey()

设置消息队列的`key`。

```php
Swoole\Process\Manager->setMsgQueueKey(int $msgQueueKey): self;
```

* **参数**

  * **`int $msgQueueKey`**
    * **功能**：消息队列的 `key`
    * **默认值**：无
    * **其它值**：无

### getMsgQueueKey()

获取消息队列的`key`。

```php
Swoole\Process\Manager->getMsgQueueKey(): int;
```

### add()

增加一个工作进程。

```php
Swoole\Process\Manager->add(callable $func, bool $enableCoroutine = false): self;
```

* **参数**

  * **`callable $func`**
    * **功能**：当前进程执行的回调函数
    * **默认值**：无
    * **其它值**：无

  * **`bool $enableCoroutine`**
    * **功能**：是否为这个进程创建协程来执行回调函数
    * **默认值**：false
    * **其它值**：无

### addBatch()

批量增加工作进程。

```php
Swoole\Process\Manager->addBatch(int $workerNum, callable $func, bool $enableCoroutine = false): self
```

* **参数**

  * **`int $workerNum`**
    * **功能**：批量增加进程的个数
    * **默认值**：无
    * **其它值**：无

  * **`callable $func`**
    * **功能**：这些进程执行的回调函数
    * **默认值**：无
    * **其它值**：无

  * **`bool $enableCoroutine`**
    * **功能**：是否为这些进程创建协程来执行回调函数
    * **默认值**：无
    * **其它值**：无

### start()

启动工作进程。

```php
Swoole\Process\Manager->start(): void
```
