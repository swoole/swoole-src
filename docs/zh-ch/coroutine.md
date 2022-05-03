# Coroutine <!-- {docsify-ignore-all} -->

本节介绍一些协程基本概念和常见问题，也可以通过 [Swoole视频教程](https://course.swoole-cloud.com/course-video/6) 观看。

从4.0版本开始`Swoole`提供了完整的`协程（Coroutine）`+ `通道（Channel）`特性，带来全新的`CSP`编程模型。

1. 开发者可以无感知的用同步的代码编写方式达到[异步IO](/learn?id=同步io异步io)的效果和性能，避免了传统异步回调所带来的离散的代码逻辑和陷入多层回调中导致代码无法维护
2. 同时由于底层封装了协程，所以对比传统的`PHP`层协程框架，开发者不需要使用[yield](https://www.php.net/manual/zh/language.generators.syntax.php)关键词来标识一个协程`IO`操作，所以不再需要对`yield`的语义进行深入理解以及对每一级的调用都修改为`yield`，这极大的提高了开发效率
3. 提供了各种类型完善的[协程客户端](/coroutine_client/init)，可以满足大部分开发者的需求。

## 什么是协程

协程可以简单理解为线程，只不过这个线程是用户态的，不需要操作系统参与，创建销毁和切换的成本非常低，和线程不同的是协程没法利用多核cpu的，想利用多核cpu需要依赖`Swoole`的多进程模型。

## 什么是channel

`channel`可以理解为消息队列，只不过是协程间的消息队列，多个协程通过`push`和`pop`操作生产消息和消费消息，用来协程之间的通讯。需要注意的是`channel`是没法跨进程的，只能一个`Swoole`进程里的协程间通讯，最典型的应用是[连接池](/coroutine/conn_pool)和[并发调用](/coroutine/multi_call)。

## 什么是协程容器

使用`Coroutine::create`或`go`方法创建协程(参考[别名小节](/other/alias?id=协程短名称))，在创建的协程中才能使用协程`API`，而协程必须创建在协程容器里面，参考[协程容器](/coroutine/scheduler)。

## 协程调度

这里将尽量通俗的讲述什么是协程调度，首先每个协程可以简单的理解为一个线程，大家知道多线程是为了提高程序的并发，同样的多协程也是为了提高并发。

用户的每个请求都会创建一个协程，请求结束后协程结束，如果同时有成千上万的并发请求，某一时刻某个进程内部会存在成千上万的协程，那么CPU资源是有限的，到底执行哪个协程的代码？

决定到底让CPU执行哪个协程的代码决断过程就是`协程调度`，`Swoole`的调度策略又是怎么样的呢？

- 首先，在执行某个协程代码的过程中发现这行代码遇到了`Co::sleep()`或者产生了网络`IO`，例如`MySQL->query()`，这肯定是一个耗时的过程，`Swoole`就会把这个Mysql连接的Fd放到[EventLoop](/learn?id=什么是eventloop)中。
      
    * 然后让出这个协程的CPU给其他协程使用：**即`yield`(挂起)**
    * 等待MySQL数据返回后就继续执行这个协程：**即`resume`(恢复)**

- 其次，如果协程的代码有CPU密集型代码，可以开启[enable_preemptive_scheduler](/other/config)，Swoole会强行让这个协程让出CPU。

## 父子协程优先级

优先执行子协程(即`go()`里面的逻辑)，直到发生协程`yield`(co::sleep处)，然后[协程调度](/coroutine?id=协程调度)到外层协程

```php
use Swoole\Coroutine;
use function Swoole\Coroutine\run;

echo "main start\n";
run(function () {
    echo "coro " . Coroutine::getcid() . " start\n";
    Coroutine::create(function () {
        echo "coro " . Coroutine::getcid() . " start\n";
        Coroutine::sleep(.2);
        echo "coro " . Coroutine::getcid() . " end\n";
    });
    echo "coro " . Coroutine::getcid() . " do not wait children coroutine\n";
    Coroutine::sleep(.1);
    echo "coro " . Coroutine::getcid() . " end\n";
});
echo "end\n";

/*
main start
coro 1 start
coro 2 start
coro 1 do not wait children coroutine
coro 1 end
coro 2 end
end
*/
```
  
## 注意事项

在使用 Swoole 编程前应该注意的地方：

### 全局变量

协程使得原有的异步逻辑同步化，但是在协程的切换是隐式发生的，所以在协程切换的前后不能保证全局变量以及`static`变量的一致性。

在 `PHP-FPM` 下可以通过全局变量获取到请求的参数，服务器的参数等，在 `Swoole` 内，**无法** 通过 `$_GET/$_POST/$_REQUEST/$_SESSION/$_COOKIE/$_SERVER`等`$_`开头的变量获取到任何属性参数。

可以使用[context](/coroutine/coroutine?id=getcontext)用协程id做隔离，实现全局变量的隔离。

### 多协程共享TCP连接

[参考](/question/use?id=client-has-already-been-bound-to-another-coroutine)
