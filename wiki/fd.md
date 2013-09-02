关于from_id和fd
-----
回调函数中经常看到它。
* from_id是来自于哪个poll线程
* fd是tcp连接的文件描述符

调用swoole_server_send/swoole_server_close函数需要传入这两个参数才能被正确的处理。如果业务中需要发送广播，需要将fd和from_id保存起来，可以用apc/redis/memcache来保存它。
    新版的swoole[>=1.6.0]不再需要from_id参数
