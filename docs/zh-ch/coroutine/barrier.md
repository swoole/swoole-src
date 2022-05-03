# Coroutine\Barrier

在 [Swoole Library](https://github.com/swoole/library) 中底层提供了一个更便捷的协程并发管理工具：`Coroutine\Barrier` 协程屏障，或者叫协程栅栏。基于 `PHP` 引用计数和 `Coroutine API` 实现。

相比于[Coroutine\WaitGroup](/coroutine/wait_group)，`Coroutine\Barrier`使用更简单一些，只需通过参数传递或者闭包的`use`语法，引入子协程函数上即可。

!> Swoole 版本 >= v4.5.5 时可用。

## 使用示例

```php
use Swoole\Coroutine\Barrier;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;
use Swoole\Coroutine;

run(function () {
    $barrier = Barrier::make();

    $count = 0;
    $N = 4;

    foreach (range(1, $N) as $i) {
        Coroutine::create(function () use ($barrier, &$count) {
            System::sleep(0.5);
            $count++;
        });
    }

    Barrier::wait($barrier);
    
    assert($count == $N);
});
```

## 执行流程

* 先使用`Barrier::make()`创建了一个新的协程屏障
* 在子协程用使用`use`语法传递屏障，增加引用计数
* 在需要等待的位置加入`Barrier::wait($barrier)`，这时会自动挂起当前协程，等待引用该协程屏障的子协程退出
* 子协程退出时会减少`$barrier`对象的引用计数，直到为`0`
* 当所有子协程完成了任务处理并退出时，`$barrier`对象引用计数为`0`，在`$barrier`对象析构函数中底层会自动恢复挂起的协程，从`Barrier::wait($barrier)`函数中返回

`Coroutine\Barrier` 是一个比 [WaitGroup](/coroutine/wait_group) 和 [Channel](/coroutine/channel) 更易用的并发控制器，大幅提升了 `PHP` 并发编程的用户体验。
