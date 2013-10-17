Swoole版本更新记录
=====

v1.6.1
----
* 增加configure可选参数--enable-msgqueue，启用此参数后将使用消息队列作为IPC方式
* 解决reload后，worker分配错误的bug
* 抢占式分配bug解决
* 解决刷warn的问题

v1.6.0
-----
* 优化UDP实现方式，实现高并发高可靠的UDP Server
* 可以切换IPC模式，队列或者Unsock
* close事件处理优化，解决丢失close的bug
* 使用全局内存池来分配内存

v1.5.9
-----
* 修复onClose回调$fd/$from_id错误的bug
* swoole_framework框架提供WebSocket支持

v1.5.8
------
* 增加swoole_connection_list接口，用于遍历所有连接
* 增加swoole_connection_info接口，用于获取连接信息
* swoole_server_send/swoole_server_close不再需要传入from_id参数
* buffer功能测试通过，已增加到setting中
* 提供对tcp_keepalive的支持
* 增加日志模块，记录运行时的警告和错误信息


v1.5.7
-----
* 不再使用clock_gettime，不需要如此高精度的时间
* 增加onWorkerStart/onWorkerStop回调函数
* 增加onMasterConnect/onMasterClose回调函数
* 可配置poll线程与worker进程间的通信方式



