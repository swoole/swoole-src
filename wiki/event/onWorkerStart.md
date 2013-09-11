onWorkerStart
-----
此事件在worker进程启动时发生。这里创建的对象可以在worker进程生命周期内使用。原型：
```php
void onWorkerStart(resource $server, int $worker_id);
```

* $worker_id是一个从0-$worker_num之间的数字，表示这个worker进程的ID
* $worker_id和进程PID没有任何关系
