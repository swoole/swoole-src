onShutdown
-----
此事件在Server结束时发生，，函数原型
```php
void onShutdown(resource $server);
```
在此之前Swoole Server已进行了如下操作

* 已关闭所有线程
* 已关闭所有worker进程
* 已close所有TCP/UDP监听端口
* 已关闭主Rector

> 强制kill进程不会回调onShutdown，如kill -9  
> 需要使用kill -15来发送SIGTREM信号到主进程才能按照正常的流程终止