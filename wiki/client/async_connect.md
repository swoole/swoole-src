TCP客户端异步连接
-----
swoole_client支持TCP异步连接，需要将connect方法的第四个参数设置1。
socket将被设置为非阻塞，connect会立即返回。PHP代码可以不必等待连接完成，继续向下执行其他的代码。
在需要send/recv数据时，先使用swoole_client_select监听可写事件，如果socket可写表示已完成连接。  

具体的代码实现，可以参考网上异步connect的文章。

