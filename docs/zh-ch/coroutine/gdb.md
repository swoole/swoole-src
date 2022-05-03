# 调试协程

使用`Swoole`协程时，可以使用下面的方法进行调试

## GDB调试

### 进入 gdb <!-- {docsify-ignore} -->

```shell
gdb php test.php
```

### gdbinit <!-- {docsify-ignore} -->

```shell
(gdb) source /path/to/swoole-src/gdbinit
```

### 设置断点 <!-- {docsify-ignore} -->

例如 `co::sleep` 函数

```shell
(gdb) b zim_swoole_coroutine_util_sleep
```

### 打印当前进程的所有协程和状态 <!-- {docsify-ignore} -->

```shell
(gdb) co_list 
coroutine 1 SW_CORO_YIELD
coroutine 2 SW_CORO_RUNNING
```

### 打印当前运行时协程的调用栈 <!-- {docsify-ignore} -->

```shell
(gdb) co_bt 
coroutine cid:[2]
[0x7ffff148a100] Swoole\Coroutine->sleep(0.500000) [internal function]
[0x7ffff148a0a0] {closure}() /home/shiguangqi/php/swoole-src/examples/coroutine/exception/test.php:7 
[0x7ffff141e0c0] go(object[0x7ffff141e110]) [internal function]
[0x7ffff141e030] (main) /home/shiguangqi/php/swoole-src/examples/coroutine/exception/test.php:10
```

### 打印指定协程id的调用栈 <!-- {docsify-ignore} -->

``` shell
(gdb) co_bt 1
[0x7ffff1487100] Swoole\Coroutine->sleep(0.500000) [internal function]
[0x7ffff14870a0] {closure}() /home/shiguangqi/php/swoole-src/examples/coroutine/exception/test.php:3 
[0x7ffff141e0c0] go(object[0x7ffff141e110]) [internal function]
[0x7ffff141e030] (main) /home/shiguangqi/php/swoole-src/examples/coroutine/exception/test.php:10 
```

### 打印全局协程的状态 <!-- {docsify-ignore} -->

```shell
(gdb) co_status 
	 stack_size: 2097152
	 call_stack_size: 1
	 active: 1
	 coro_num: 2
	 max_coro_num: 3000
	 peak_coro_num: 2
```

## PHP代码调试

遍历当前进程内的所有协程，并打印调用栈。

```php
Swoole\Coroutine::listCoroutines(): Swoole\Coroitine\Iterator
```

!> 需要`4.1.0`或更高版本

* 返回迭代器，可使用`foreach`遍历，或使用`iterator_to_array`转为数组

```php
use Swoole\Coroutine;
$coros = Coroutine::listCoroutines();
foreach($coros as $cid)
{
	var_dump(Coroutine::getBackTrace($cid));
}
```

可以参考 [Swoole微课程中的视频教程](https://course.swoole-cloud.com/course-video/66)