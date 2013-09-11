onStart
-----
Server启动在主进程的主线程回调此函数，函数原型
```php
void onStart(resource $server);
```

在此事件之前Swoole Server已进行了如下操作

* 已创建了manager进程
* 已创建了worker子进程
* 已监听所有TCP/UDP端口
* 已监听了定时器

接下来要执行
* 主Reactor开始接收事件，客户端可以connect到Server

onStart事件在Master进程的主线程中被调用。
> 在onStart中创建的**全局资源对象**不能在worker进程中被使用，因为发生onStart调用时，worker进程已经创建好了。  
> 新创建的对象在主进程内，worker进程无法访问到此内存区域。  
> 因此全局对象创建的代码需要放置在swoole_server_start之前。