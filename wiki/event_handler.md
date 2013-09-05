swoole_server_handler设置事件回调
=====

使用方法：
```php
swoole_server_handler($serv, 'onStart', 'my_onStart');
function my_onStart($serv)
{
    echo "Server：start\n";
}
```
第一个参数是swoole的资源对象，第二个参数是回调的名称，第三个函数是回调的PHP函数，可以是字符串，数组，匿名函数。比如
```php
swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onStart', array($this, 'my_onStart'));
swoole_server_handler($serv, 'onStart', 'myClass::onStart');
```

onStart
-----
此事件在Server启动时发生，在此事件之前Swoole Server已进行了如下操作

* 已创建了manager进程
* 已创建了worker子进程
* 已监听所有TCP/UDP端口
* 已监听了定时器

接下来要执行
* 主Reactor开始接收事件，客户端可以connect到Server

onStart事件在Master进程的主线程中被调用。需要注意，在onStart中创建的对象，不能在worker进程中被使用，因为发生onStart调用时，worker进程已经创建好了。新创建的对象在主进程内，worker进程无法访问到此内存区域。因此全局对象创建的代码需要放置在swoole_server_start之前。

onShutdown
-----
此事件在Server结束时发生，在此事件之前Swoole Server已进行了如下操作

* 已关闭所有线程
* 已关闭所有worker进程
* 已close所有TCP/UDP监听端口
* 已关闭主Rector

注意强制kill进程的话，不会回调onShutdown，如kill -9。需要使用kill -15来发送信号到主进程才能按照正常的流程终止。


onWorkerStart
-----
此事件在worker进程启动时发生，这里创建的对象，可以在worker进程生命周期内使用。


onWorkerStop
-----
此事件在worker进程结束时发生。


onConnect/onClose
-----
有新的连接到来/结束时，在worker进程中被回调。注意这2个回调发生在worker进程内，而不是主进程。如果需要在主进程处理连接/关闭事件，请注册onMasterConnect/onMasterClose回调。


onMasterConnect/onMasterClose
-----
作用类似onConnect/onClose，但是在Master进程中调用的。

onReceive
-----
接收到数据时回调此函数，发生在worker进程中。swoole只负责底层通信，数据的格式，解包打包，包完整性检测需要放在应用层处理。
onReceive到的数据，需要检查是不是完整的包，是否需要继续等待数据。代码中可以增加一个 $buffer = array()，使用$fd作为key，来保存上下文数据。

默认情况下，同一个fd会被分配到同一个worker中，所以数据可以拼接起来。

关于粘包问题，如SMTP协议，客户端可能会同时发出2条指令。在swoole中可能是一次性收到的，这时应用层需要自行拆包。smtp是通过\r\n来分包的，所以业务代码中需要 explode("\r\n", $data)来拆分数据包。



