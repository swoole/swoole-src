# 服务端(协程风格) <!-- {docsify-ignore-all} -->

`Swoole\Coroutine\Server` 与 [异步风格](/server/init) 的服务端不同之处在于，`Swoole\Coroutine\Server` 是完全协程化实现的服务器，参考 [完整例子](/coroutine/server?id=完整示例)。
 
## 优点：

- 不需要设置事件回调函数。建立连接、接收数据、发送数据、关闭连接都是顺序的，没有 [异步风格](/server/init) 的并发问题，例如：

```php
$serv = new Swoole\Server("127.0.0.1", 9501);

//监听连接进入事件
$serv->on('Connect', function ($serv, $fd) {
    $redis = new Redis();
    $redis->connect("127.0.0.1",6379);//此处OnConnect的协程会挂起
    Co::sleep(5);//此处sleep模拟connect比较慢的情况
    $redis->set($fd,"fd $fd connected");
});

//监听数据接收事件
$serv->on('Receive', function ($serv, $fd, $reactor_id, $data) {
    $redis = new Redis();
    $redis->connect("127.0.0.1",6379);//此处onReceive的协程会挂起
    var_dump($redis->get($fd));//有可能onReceive的协程的redis连接先建立好了，上面的set还没有执行，此处get会是false，产生逻辑错误
});

//监听连接关闭事件
$serv->on('Close', function ($serv, $fd) {
    echo "Client: Close.\n";
});

//启动服务器
$serv->start();
```

上述`异步风格`的服务器，无法保证事件的顺序，即无法保证`onConnect`执行结束后才进入`onReceive`，因为在开启协程化后，`onConnect`和`onReceive`回调都会自动创建协程，遇到IO会产生[协程调度](/coroutine?id=协程调度)，异步风格的无法保证调度顺序，而协程风格的服务端没有这个问题。  

- 可以动态的开启关闭服务，异步风格的服务在`start()`被调用之后就什么也干不了了，而协程风格的可以动态开启关闭服务。  

## 缺点：

- 协程风格的服务不会自动创建多个进程，需要配合[Process\Pool](/process/process_pool)模块使用才能利用多核。  
- 协程风格服务其实是对[Co\Socket](/coroutine_client/socket)模块的封装，所以用协程风格的需要对socket编程有一定经验。  
- 目前封装层级没有异步风格服务器那么高，有些东西需要自己手动实现，比如`reload`功能需要自己监听信号来做逻辑。
