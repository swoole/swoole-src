Worker进程
-----
Swoole提供了完善的进程管理机制，当Worker进程异常退出，如发生PHP的致命错误、被其他程序误杀，或达到max_request次数之后正常退出。主进程会重新拉起新的Worker进程。
Worker进程内可以像普通的apache+php或者php-fpm中写代码。不需要像Node.js那样写异步回调的代码。

回调函数中，onWorkerStart/onWorkerStop/onClose/onConnect/onRecieve都是在worker进程中调用。
onStart/onShutdown/onTimer回调在主进程的主线程内调用。


