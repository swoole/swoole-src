swoole_client_select函数
-----
swoole_client的并行处理中用了select来做IO事件循环。为什么要用select呢？  
因为client一般不会有太多连接，而且大部分socket会很快接收到响应数据。  
在少量连接的情况下select比epoll性能更好。另外select更简单。 
函数原型：
```php
int swoole_client_select(array &$read, array &$write, array &$error, float $timeout);
```
swoole_client_select接受4个参数，$read,$write,$error分别是可读/可写/错误的文件描述符。  
这3个参数必须是数组变量的引用。数组的元素必须为swoole_client对象。  
$timeout参数是select的超时时间，单位为秒，接受浮点数。

调用成功后，会返回事件的数量，并修改$read/$write/$error数组。使用foreach遍历数组，然后执行$item->recv/$item->send来收发数据。或者调用$item->close()或unset($item)来关闭socket。
