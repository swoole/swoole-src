内核参数调整
-----

* ulimit -n 要调整为100000甚至更大。  
如何调这个参数，可以参考网上的一些文章。命令行下执行 ulimit -n 100000即可修改。如果不能修改，需要设置  /etc/security/limits.conf，加入
	* hard nofile 100000
	* soft nofile 100000
* net.unix.max_dgram_qlen swoole使用unix socket dgram来做进程间通信，如果请求量很大，需要调整此参数。系统默认为10，可以设置为100。  
或者增加worker进程的数量，减少单个worker进程分配的请求量。
* net.core.wmem_max 修改此参数增加socket缓存区的内存大小  
	* net.core.wmem_default = 8388608
	* net.core.rmem_default = 8388608
	* net.core.rmem_max = 16777216
	* net.core.wmem_max = 16777216
* net.ipv4.tcp_tw_reuse 是否socket reuse，此函数的作用是，Server重启时可以快速重新使用监听的端口。如果没有设置此参数，会导致server重启时发生端口未及时释放而启动失败
* net.ipv4.tcp_tw_recycle 使用socket快速回收，短连接Server需要开启此参数
* kernel.msgmnb = 65536, kernel.msgmax = 65536 如果使用消息队列作为IPC，请修改此参数
