# 使用问题

## Swoole性能如何

> QPS对比

使用 Apache-Bench工具(ab) 对Nginx静态页、Golang HTTP程序、PHP7+Swoole HTTP程序进行压力测试。在同一台机器上，进行并发100共100万次HTTP请求的基准测试中，QPS对比如下：

| 软件 | QPS | 软件版本 |
| --- | --- | --- |
| Nginx | 164489.92	| nginx/1.4.6 (Ubuntu) |
| Golang |	166838.68 |	go version go1.5.2 linux/amd64 |
| PHP7+Swoole |	287104.12 |	Swoole-1.7.22-alpha |
| Nginx-1.9.9 |	245058.70 |	nginx/1.9.9 |

!> 注：Nginx-1.9.9的测试中，已关闭access_log，启用open_file_cache缓存静态文件到内存

> 测试环境

* CPU：Intel® Core™ i5-4590 CPU @ 3.30GHz × 4
* 内存：16G
* 磁盘：128G SSD
* 操作系统：Ubuntu14.04 (Linux 3.16.0-55-generic)

> 压测方法

```shell
ab -c 100 -n 1000000 -k http://127.0.0.1:8080/
```

> VHOST配置

```nginx
server {
    listen 80 default_server;
    root /data/webroot;
    index index.html;
}
```

> 测试页面

```html
<h1>Hello World!</h1>
```

> 进程数量

Nginx开启了4个Worker进程
```shell
htf@htf-All-Series:~/soft/php-7.0.0$ ps aux|grep nginx
root      1221  0.0  0.0  86300  3304 ?        Ss   12月07   0:00 nginx: master process /usr/sbin/nginx
www-data  1222  0.0  0.0  87316  5440 ?        S    12月07   0:44 nginx: worker process
www-data  1223  0.0  0.0  87184  5388 ?        S    12月07   0:36 nginx: worker process
www-data  1224  0.0  0.0  87000  5520 ?        S    12月07   0:40 nginx: worker process
www-data  1225  0.0  0.0  87524  5516 ?        S    12月07   0:45 nginx: worker process
```

> Golang

测试代码

```go
package main

import (
    "log"
    "net/http"
    "runtime"
)

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU() - 1)

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("Last-Modified", "Thu, 18 Jun 2015 10:24:27 GMT")
        w.Header().Add("Accept-Ranges", "bytes")
        w.Header().Add("E-Tag", "55829c5b-17")
        w.Header().Add("Server", "golang-http-server")
        w.Write([]byte("<h1>\nHello world!\n</h1>\n"))
    })

    log.Printf("Go http Server listen on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

> PHP7+Swoole

PHP7已启用`OPcache`加速器。

测试代码

```php
$http = new Swoole\Http\Server("127.0.0.1", 9501, SWOOLE_BASE);

$http->set([
    'worker_num' => 4,
]);

$http->on('request', function ($request, Swoole\Http\Server $response) {
    $response->header('Last-Modified', 'Thu, 18 Jun 2015 10:24:27 GMT');
    $response->header('E-Tag', '55829c5b-17');
    $response->header('Accept-Ranges', 'bytes');    
    $response->end("<h1>\nHello Swoole.\n</h1>");
});

$http->start();
```

> **全球Web框架权威性能测试 Techempower Web Framework Benchmarks**

最新跑分测试结果地址: [techempower](https://www.techempower.com/benchmarks/#section=test&runid=9d5522a6-2917-467a-9d7a-8c0f6a8ed790)

Swoole领跑**动态语言第一**

数据库IO操作测试, 使用基本业务代码无特殊优化

**性能超过所有静态语言框架(使用MySQL而不是PostgreSQL)**

## Swoole如何维持TCP长连接

关于TCP长连接维持有2组配置[tcp_keepalive](/server/setting?id=open_tcp_keepalive)和[heartbeat](/server/setting?id=heartbeat_check_interval)，使用方法和注意事项参考
[Swoole官方视频教程](https://course.swoole-cloud.com/course-video/10)

## Swoole如何正确的重启服务

在日常开发中，修改了PHP代码后经常需要重启服务让代码生效，一台繁忙的后端服务器随时都在处理请求，如果管理员通过`kill`进程方式来终止/重启服务器程序，可能导致刚好代码执行到一半终止，没法保证整个业务逻辑的完整性。

`Swoole`提供了柔性终止/重启的机制，管理员只需要向`Server`发送特定的信号或者调用`reload`方法，工作进程就可以结束，并重新拉起。具体请参考[reload()](/server/methods?id=reload)
 
但有几点要注意：

首先要注意新修改的代码必须要在`OnWorkerStart`事件中重新载入才会生效，比如某个类在`OnWorkerStart`之前就通过composer的autoload载入了就是不可以的。

其次`reload`还要配合这两个参数[max_wait_time](/server/setting?id=max_wait_time)和[reload_async](/server/setting?id=reload_async)，设置了这两个参数之后就能实现`异步安全重启`。

如果没有此特性，Worker进程收到重启信号或达到[max_request](/server/setting?id=max_request)时，会立即停止服务，这时`Worker`进程内可能仍然有事件监听，这些异步任务将会被丢弃。设置上述参数后会先创建新的`Worker`，旧的`Worker`在完成所有事件之后自行退出，即`reload_async`。

如果旧的`Worker`一直不退出，底层还增加了一个定时器，在约定的时间([max_wait_time](/server/setting?id=max_wait_time)秒)内旧的`Worker`没有退出，底层会强行终止，并会产生一个 [WARNING](/question/use?id=forced-to-terminate) 报错。

示例：

```php
<?php
$serv = new Swoole\Server('0.0.0.0', 9501, SWOOLE_PROCESS);
$serv->set(array(
    'worker_num' => 1,
    'max_wait_time' => 60,
    'reload_async' => true,
));
$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {

    echo "[#" . $serv->worker_id . "]\tClient[$fd] receive data: $data\n";
    
    Swoole\Timer::tick(5000, function () {
        echo 'tick';
    });
});

$serv->start();
```

例如上面的代码，如果没有 reload_async 那么 onReceive 中创建的定时器将丢失，没有机会处理定时器中的回调函数。

### 进程退出事件

为了支持异步重启特性，底层新增了一个[onWorkerExit](/server/events?id=onWorkerExit)事件，当旧的`Worker`即将退出时，会触发`onWorkerExit`事件，在此事件回调函数中，应用层可以尝试清理某些长连接`Socket`，直到[事件循环](/learn?id=什么是eventloop)中没有fd或者达到了[max_wait_time](/server/setting?id=max_wait_time)退出进程。

```php
$serv->on('WorkerExit', function (Swoole\Server $serv, $worker_id) {
    $redisState = $serv->redis->getState();
    if ($redisState == Swoole\Redis::STATE_READY or $redisState == Swoole\Redis::STATE_SUBSCRIBE)
    {
        $serv->redis->close();
    }
});
```

同时在 [Swoole Plus](https://www.swoole.com/swoole_plus) 中增加了检测文件变化的功能，可以不用手动reload或者发送信号，文件变更自动重启worker。

## 为什么不要send完后立即close就是不安全的

send完后立即close就是不安全的，无论是服务器端还是客户端。

send操作成功只是表示数据成功地写入到操作系统socket缓存区，不代表对端真的接收到了数据。究竟操作系统有没有发送成功，对方服务器是否收到，服务器端程序是否处理，都没办法确切保证。

> close后的逻辑请看下面的linger设置相关

这个逻辑和电话沟通是一个道理，A告诉B一个事情，A说完了就挂掉电话。那么B听到没有，A是不知道的。如果A说完事情，B说好，然后B挂掉电话，就绝对是安全的。

linger设置

一个`socket`在close时，如果发现缓冲区仍然有数据，操作系统底层会根据`linger`设置决定如何处理

```c
struct linger
{
     int l_onoff;
     int l_linger;
};
```

* l_onoff = 0，close时立刻返回，底层会将未发送完的数据发送完成后再释放资源，也就是优雅的退出。
* l_onoff != 0，l_linger = 0，close时会立刻返回，但不会发送未发送完成的数据，而是通过一个RST包强制的关闭socket描述符，也就是强制的退出。
* l_onoff !=0，l_linger > 0， closes时不会立刻返回，内核会延迟一段时间，这个时间就由l_linger的值来决定。如果超时时间到达之前，发送完未发送的数据(包括FIN包)并得到另一端的确认，close会返回正确，socket描述符优雅性退出。否则close会直接返回错误值，未发送数据丢失，socket描述符被强制性退出。如果socket描述符被设置为非堵塞型，则close会直接返回值。

## client has already been bound to another coroutine

对于一个`TCP`连接来说Swoole底层允许同时只能有一个协程进行读操作、一个协程进行写操作。也就是说不能有多个协程对一个TCP进行读/写操作，底层会抛出绑定错误:

```shell
Fatal error: Uncaught Swoole\Error: Socket#6 has already been bound to another coroutine#2, reading or writing of the same socket in coroutine#3 at the same time is not allowed 
```

重现代码：

```php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function() {
    $cli = new Client('www.xinhuanet.com', 80);
    Coroutine::create(function () use ($cli) {
        $cli->get('/');
    });
    Coroutine::create(function () use ($cli) {
        $cli->get('/');
    });
});
```

解决方案参考：https://wenda.swoole.com/detail/107474

!> 此限制对于所有多协程环境都有效，最常见的就是在[onReceive](/server/events?id=onreceive)等回调函数中去共用一个TCP连接，因为此类回调函数会自动创建一个协程，
那有连接池需求怎么办？`Swoole`内置了[连接池](/coroutine/conn_pool)可以直接使用，或手动用`channel`封装连接池。

## Call to undefined function Co\run()

本文档中的大部分示例都使用了`Co\run()`来创建一个协程容器，[了解什么是协程容器](/coroutine?id=什么是协程容器)

如果遇到如下错误：

```bash
PHP Fatal error:  Uncaught Error: Call to undefined function Co\run()

PHP Fatal error:  Uncaught Error: Call to undefined function go()
```

说明你的`Swoole`扩展版本小于`v4.4.0`或者手动关闭了[协程短名称](/other/alias?id=协程短名称)，提供以下解决方法

* 如果是版本过低，则请升级扩展版本至`>= v4.4.0`或使用`go`关键字替换`Co\run`来创建协程；
* 如果是关闭了协程短名称，则请打开[协程短名称](/other/alias?id=协程短名称)；
* 使用[Coroutine::create](/coroutine/coroutine?id=create)方法替换`Co\run`或`go`来创建协程；
* 使用全名：`Swoole\Coroutine\run`；

## 是否可以共用1个Redis或MySQL连接

绝对不可以。必须每个进程单独创建`Redis`、`MySQL`、`PDO`连接，其他的存储客户端同样也是如此。原因是如果共用1个连接，那么返回的结果无法保证被哪个进程处理，持有连接的进程理论上都可以对这个连接进行读写，这样数据就发生错乱了。

**所以在多个进程之间，一定不能共用连接**

* 在[Swoole\Server](/server/init)中，应当在[onWorkerStart](/server/events?id=onworkerstart)中创建连接对象
* 在[Swoole\Process](/process/process)中，应当在[Swoole\Process->start](/process/process?id=start)后，子进程的回调函数中创建连接对象
* 此问题所述信息对使用`pcntl_fork`的程序同样有效

示例：

```php
$server = new Swoole\Server('0.0.0.0', 9502);

//必须在onWorkerStart回调中创建redis/mysql连接
$server->on('workerstart', function($server, $id) {
    $redis = new Redis();
	$redis->connect('127.0.0.1', 6379);
	$server->redis = $redis;
});

$server->on('receive', function (Swoole\Server $server, $fd, $reactor_id, $data) {	
	$value = $server->redis->get("key");
	$server->send($fd, "Swoole: ".$value);
});

$server->start();
```

## 连接已关闭问题

如以下提示

```bash
NOTICE swFactoryProcess_finish (ERRNO 1004): send 165 byte failed, because connection[fd=123] is closed

NOTICE swFactoryProcess_finish (ERROR 1005): connection[fd=123] does not exists
```

服务端响应时, 客户端已经切断了连接导致

常见于:

* 浏览器疯狂刷新页面(还没加载完就刷掉了)
* ab压测到一半取消
* wrk基于时间的压测 (时间到了未完成的请求会被取消)

以上几种情况均属于正常现象, 可以忽略, 所以该错误的级别是NOTICE

如由于其它情况无缘无故出现大量连接断开时, 才需要注意

```bash
WARNING swWorker_discard_data (ERRNO 1007): [2] received the wrong data[21 bytes] from socket#75

WARNING Worker_discard_data (ERRNO 1007): [2] ignore data[5 bytes] received from session#2
```

同样的，这个错误也表示连接已经关闭了，收到的数据会被丢弃。参考[discard_timeout_request](/server/setting?id=discard_timeout_request)

## connected属性和连接状态不一致

4.x协程版本后, `connected`属性不再会实时更新, [isConnect](/client?id=isconnected)方法不再可靠

### 原因

协程的目标是和同步阻塞的编程模型一致, 同步阻塞模型中不会有实时更新连接状态的概念, 如PDO, curl等, 都没有连接的概念, 而是在IO操作时返回错误或抛出异常才能发现连接断开

Swoole底层通用的做法是, IO错误时, 返回false(或空白内容表示连接已断开), 并在客户端对象上设置相应的错误码, 错误信息

### 注意

尽管以前的异步版本支持"实时"更新`connected`属性, 但实际上并不可靠, 连接可能会在你检查后马上就断开了

## Connection refused是怎么回事

telnet 127.0.0.1 9501 时发生Connection refused，这表示服务器未监听此端口。

* 检查程序是否执行成功: ps aux
* 检查端口是否在监听: netstat -lp
* 查看网络通信通信过程是否正常: tcpdump traceroute

## Resource temporarily unavailable [11]

客户端swoole_client在`recv`时报

```shell
swoole_client::recv(): recv() failed. Error: Resource temporarily unavailable [11]
```

这个错误表示，服务器端在规定的时间内没有返回数据，接收超时了。

* 可以通过tcpdump查看网络通信过程，检查服务器是否发送了数据
* 服务器的`$serv->send`函数需要检测是否返回了true
* 外网通信时，耗时较多需要调大swoole_client的超时时间

## worker exit timeout, forced to terminate :id=forced-to-terminate

发现形如以下报错：

```bash
WARNING swWorker_reactor_try_to_exit (ERRNO 9012): worker exit timeout, forced to terminate
```

表示在约定的时间 ([max_wait_time](/server/setting?id=max_wait_time)秒) 内此 Worker 没有退出，Swoole底层强行终止此进程。

可使用如下代码进行复现：

```php
use Swoole\Timer;

$server = new Swoole\Server('127.0.0.1', 9501);
$server->set(
    [
        'reload_async' => true,
        'max_wait_time' => 4,
    ]
);

$server->on('workerStart', function (Swoole\Server $server, int $wid) {
    if ($wid === 0) {
        Timer::tick(5000, function () {
            echo 'tick';
        });
        Timer::after(500, function () use ($server) {
            $server->shutdown();
        });
    }
});

$server->on('receive', function () {

});

$server->start();
```

## Unable to find callback function for signal Broken pipe: 13

发现形如以下报错：

```bash
WARNING swSignalfd_onSignal (ERRNO 707): Unable to find callback function for signal Broken pipe: 13
```

表示向已断开的连接发送了数据，一般是因为没有判断发送的返回值，返回失败了还在继续发送

## 学习Swoole需要掌握哪些基础知识

### 多进程/多线程

* 了解`Linux`操作系统进程和线程的概念
* 了解`Linux`进程/线程切换调度的基本知识
* 了解进程间通信的基本知识，如管道、`UnixSocket`、消息队列、共享内存

### SOCKET

* 了解`SOCKET`的基本操作如`accept/connect`、`send/recv`、`close`、`listen`、`bind`
* 了解`SOCKET`的接收缓存区、发送缓存区、阻塞/非阻塞、超时等概念

### IO复用

* 了解`select`/`poll`/`epoll`
* 了解基于`select`/`epoll`实现的事件循环，`Reactor`模型
* 了解可读事件、可写事件

### TCP/IP网络协议

* 了解`TCP/IP`协议
* 了解`TCP`、`UDP`传输协议

### 调试工具

* 使用 [gdb](/other/tools?id=gdb) 调试`Linux`程序
* 使用 [strace](/other/tools?id=strace) 跟踪进程的系统调用
* 使用 [tcpdump](/other/tools?id=tcpdump) 跟踪网络通信过程
* 其他`Linux`系统工具，如ps、[lsof](/other/tools?id=lsof)、top、vmstat、netstat、sar、ss等

## Object of class Swoole\Curl\Handler could not be converted to int

在使用 [SWOOLE_HOOK_CURL](/runtime?id=swoole_hook_curl) 时，发生报错：

```bash
PHP Notice:  Object of class Swoole\Curl\Handler could not be converted to int

PHP Warning: curl_multi_add_handle() expects parameter 2 to be resource, object given
```

原因是 hook 后的 curl 不再是一个 resource 类型，而是 object 类型，所以不支持转换为 int 类型。

!> `int` 的问题建议联系 SDK 方修改代码，在PHP8中 curl 不再是 resource 类型，而是 object 类型。

解决方法有三种：

1. 不开启 [SWOOLE_HOOK_CURL](/runtime?id=swoole_hook_curl)。不过从 [v4.5.4](/version/log?id=v454) 版本开始，[SWOOLE_HOOK_ALL](/runtime?id=swoole_hook_all) 默认包含了 [SWOOLE_HOOK_CURL](/runtime?id=swoole_hook_curl)，可以设置为`SWOOLE_HOOK_ALL ^ SWOOLE_HOOK_CURL`来关闭 [SWOOLE_HOOK_CURL](/runtime?id=swoole_hook_curl)

2. 使用 Guzzle 的SDK，可以替换 Handler 来实现协程化

3. 从Swoole `v4.6.0` 版本开始可以使用[SWOOLE_HOOK_NATIVE_CURL](/runtime?id=swoole_hook_native_curl)来代替[SWOOLE_HOOK_CURL](/runtime?id=swoole_hook_curl)

## 同时使用一键协程化和Guzzle 7.0+的时候，发起请求后将结果直接输出在终端 :id=hook_guzzle

复现代码如下

```php
// composer require guzzlehttp/guzzle
include __DIR__ . '/vendor/autoload.php';

use GuzzleHttp\Client;
use Swoole\Coroutine;

// v4.5.4之前的版本
//Coroutine::set(['hook_flags' => SWOOLE_HOOK_ALL | SWOOLE_HOOK_CURL]);
Coroutine::set(['hook_flags' => SWOOLE_HOOK_ALL]);
Coroutine\run(function () {
    $client = new Client();
    $url = 'http://baidu.com';
    $res = $client->request('GET', $url);
    var_dump($res->getBody()->getContents());
});

// 请求结果会直接输出，而不是打印出来的
//<html>
//<meta http-equiv="refresh" content="0;url=http://www.baidu.com/">
//</html>
//string(0) ""
```

!> 解决方法和上一个问题一致。不过此问题已在 Swoole 版本 >= `v4.5.8` 中修复。

## Error: No buffer space available[55]

可以忽略此错误。这个错误就是 [socket_buffer_size](/server/setting?id=socket_buffer_size) 选项过大，个别系统不接受，并不影响程序的运行。

## GET/POST请求的最大尺寸

### GET请求最大8192

GET请求只有一个Http头，Swoole底层使用固定大小的内存缓存区8K，并且不可修改。如果请求不是正确的Http请求，将会出现错误。底层会抛出以下错误：

```bash
WARN swReactorThread_onReceive_http_request: http header is too long.
```

### POST文件上传

最大尺寸受到 [package_max_length](/server/setting?id=package_max_length) 配置项限制，默认为2M，可以调用 [Server->set](/server/methods?id=set) 传入新的值修改尺寸。Swoole底层是全内存的，因此如果设置过大可能会导致大量并发请求将服务器资源耗尽。

计算方法：`最大内存占用` = `最大并发请求数` * `package_max_length` 
