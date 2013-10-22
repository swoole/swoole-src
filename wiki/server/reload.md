swoole_server_reload柔性终止/重启策略
-----
一台繁忙的后端服务器随时都在处理请求，如果管理员通过kill进程方式来终止/重启服务器程序，可能导致刚好代码执行到一半终止。
这种情况下会产生数据的不一致。如交易系统中，支付逻辑的下一段是发货，假设在支付逻辑之后进程被终止了。会导致用户支付了货币，但并没有发货，后果非常严重。

Swoole提供了柔性终止/重启的机制，管理员只需要向SwooleServer发送特定的信号，Server的worker进程可以安全的结束。

* SIGTREM: 向主进程发送此信号服务器将安全终止
* SIGUSR1: 向管理进程发送SIGUSR1信号，将平稳地restart所有worker进程，在PHP代码中可以调用swoole_server_reload($serv)完成此操作
