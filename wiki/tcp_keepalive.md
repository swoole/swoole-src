tcp keepalive设置
=====
在TCP中有一个Keep-Alive的机制可以检测死连接，应用层如果对于死链接周期不敏感或者没有实现心跳机制，可以使用操作系统提供的keepalive机制来踢掉死链接。
在server_swoole_set中增加open_tcp_keepalive=>1表示启用tcp keepalive。
另外，有3个选项可以对keepalive的细节进行调整。

tcp_keepidle
-----
单位秒，连接在n秒内没有数据请求，将开始对此连接进行探测。

tcp_keepcount
-----
探测的次数，超过次数后将close此连接。

tcp_keepinterval
-----
探测的间隔时间，单位秒。
