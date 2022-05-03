# 进程间锁 Lock

`PHP`代码中可以很方便地创建一个锁，用来实现数据同步。`Lock`类支持`5`种锁的类型

锁类型 | 说明
---|---
SWOOLE_MUTEX | 互斥锁
SWOOLE_RWLOCK | 读写锁
SWOOLE_SPINLOCK | 自旋锁
SWOOLE_FILELOCK | 文件锁(废弃)
SWOOLE_SEM | 信号量(废弃)

!> 请勿在[onReceive](/server/events?id=onreceive)等回调函数中创建锁，否则内存会持续增长，造成内存泄漏。

## 使用示例

```php
$lock = new Swoole\Lock(SWOOLE_MUTEX);
echo "[Master]create lock\n";
$lock->lock();
if (pcntl_fork() > 0)
{
  sleep(1);
  $lock->unlock();
} 
else
{
  echo "[Child] Wait Lock\n";
  $lock->lock();
  echo "[Child] Get Lock\n";
  $lock->unlock();
  exit("[Child] exit\n");
}
echo "[Master]release lock\n";
unset($lock);
sleep(1);
echo "[Master]exit\n";
```

## 警告

!> 在协程中无法使用锁，请谨慎使用，不要在`lock`和`unlock`操作中间使用可能引起协程切换的`API`。

### 错误示例

!> 此代码在协程模式下`100%`死锁 参考[此文章](https://course.swoole-cloud.com/article/2)

```php
$lock = new Swoole\Lock();
$c = 2;

while ($c--) {
  go(function () use ($lock) {
      $lock->lock();
      Co::sleep(1);
      $lock->unlock();
  });
}
```

## 方法

### __construct()

构造函数。

```php
Swoole\Lock::__construct(int $type = SWOOLE_MUTEX, string $lockfile = '');
```

!> 不要循环创建/销毁锁的对象，否则会发生内存泄漏。

  * **参数** 

    * **`int $type`**
      * **功能**：锁的类型
      * **默认值**：`SWOOLE_MUTEX`【互斥锁】
      * **其它值**：无

    * **`string $lockfile`**
      * **功能**：指定文件锁的路径【当类型为`SWOOLE_FILELOCK`时必须传入】
      * **默认值**：无
      * **其它值**：无

!> 每一种类型的锁支持的方法都不一样。如读写锁、文件锁可以支持`$lock->lock_read()`。另外除文件锁外，其他类型的锁必须在父进程内创建，这样`fork`出的子进程之间才可以互相争抢锁。

### lock()

加锁操作。如果有其他进程持有锁，那这里将进入阻塞，直到持有锁的进程`unlock()`释放锁。

```php
Swoole\Lock->lock(): bool
```

### trylock()

加锁操作。与`lock`方法不同的是，`trylock()`不会阻塞，它会立即返回。

```php
Swoole\Lock->trylock(): bool
```

  * **返回值**

    * 加锁成功返回`true`，此时可以修改共享变量
    * 加锁失败返回`false`，表示有其他进程持有锁

!> `SWOOlE_SEM` 信号量没有`trylock`方法

### unlock()

释放锁。

```php
Swoole\Lock->unlock(): bool
```

### lock_read()

只读加锁。

```php
Swoole\Lock->lock_read(): bool
```

* 在持有读锁的过程中，其他进程依然可以获得读锁，可以继续发生读操作；
* 但不能`$lock->lock()`或`$lock->trylock()`，这两个方法是获取独占锁，在独占锁加锁时，其他进程无法再进行任何加锁操作，包括读锁；
* 当另外一个进程获得了独占锁(调用`$lock->lock()`/`$lock->trylock()`)时，`$lock->lock_read()`会发生阻塞，直到持有独占锁的进程释放锁。

!> 只有`SWOOLE_RWLOCK`和`SWOOLE_FILELOCK`类型的锁支持只读加锁

### trylock_read()

加锁。此方法与`lock_read()`相同，但是非阻塞的。

```php
Swoole\Lock->trylock_read(): bool
```

!> 调用会立即返回，必须检测返回值以确定是否拿到了锁。

### lockwait()

加锁操作。作用与`lock()`方法一致，但`lockwait()`可以设置超时时间。

```php
Swoole\Lock->lockwait(float $timeout = 1.0): bool
```

  * **参数** 

    * **`float $timeout`**
      * **功能**：指定超时时间
      * **值单位**：秒【支持浮点型，如`1.5`表示`1s`+`500ms`】
      * **默认值**：`1`
      * **其它值**：无

  * **返回值**

    * 在规定的时间内未获得锁，返回`false`
    * 加锁成功返回`true`

!> 只有`Mutex`类型的锁支持`lockwait`
