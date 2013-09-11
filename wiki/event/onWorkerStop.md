onWorkerStop
-----
此事件在worker进程终止时发生。在此函数中可以回收worker进程申请的各类资源。原型：
```php
void onWorkerStop(resource $server, int $worker_id);
```

* $worker_id是一个从0-$worker_num之间的数字，表示这个worker进程的ID
* $worker_id和进程PID没有任何关系
