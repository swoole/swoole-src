# 属性

### $setting

[Server->set()](/server/methods?id=set)函数所设置的参数会保存到`Server->$setting`属性上。在回调函数中可以访问运行参数的值。

```php
Swoole\Server->setting
```

  * **示例**

```php
$server = new Swoole\Server('127.0.0.1', 9501);
$server->set(array('worker_num' => 4));

echo $server->setting['worker_num'];
```

### $master_pid

返回当前服务器主进程的`PID`。

```php
Swoole\Server->master_pid
```

!> 只能在`onStart/onWorkerStart`之后获取到

  * **示例**

```php
$server = new Swoole\Server("127.0.0.1", 9501);
$server->on('start', function ($server){
    echo $server->master_pid;
});
$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $server->send($fd, 'Swoole: '.$data);
    $server->close($fd);
});
$server->start();
```

### $manager_pid

返回当前服务器管理进程的`PID`。

```php
Swoole\Server->manager_pid
```

!> 只能在`onStart/onWorkerStart`之后获取到

  * **示例**

```php
$server = new Swoole\Server("127.0.0.1", 9501);
$server->on('start', function ($server){
    echo $server->manager_pid;
});
$server->on('receive', function ($server, $fd, $reactor_id, $data) {
    $server->send($fd, 'Swoole: '.$data);
    $server->close($fd);
});
$server->start();
```
    
### $worker_id

得到当前`Worker`进程的编号，包括 [Task进程](/learn?id=taskworker进程)。

```php
Swoole\Server->worker_id: int
```
  * **示例**

```php
$server = new Swoole\Server('127.0.0.1', 9501);
$server->set([
    'worker_num' => 8,
    'task_worker_num' => 4,
]);
$server->on('WorkerStart', function ($server, int $workerId) {
    if ($server->taskworker) {
        echo "task workerId：{$workerId}\n";
        echo "task worker_id：{$server->worker_id}\n";
    } else {
        echo "workerId：{$workerId}\n";
        echo "worker_id：{$server->worker_id}\n";
    }
});
$server->on('Receive', function ($server, $fd, $reactor_id, $data) {
});
$server->on('Task', function ($serv, $task_id, $reactor_id, $data) {
});
$server->start();
```

  * **提示**

    * 这个属性与[onWorkerStart](/server/events?id=onworkerstart)时的`$workerId`是相同的。
    * `Worker`进程编号范围是`[0, $server->setting['worker_num'] - 1]`
    * [Task进程](/learn?id=taskworker进程)编号范围是 `[$server->setting['worker_num'], $server->setting['worker_num'] + $server->setting['task_worker_num'] - 1]`

!> 工作进程重启后`worker_id`的值是不变的

### $worker_pid

得到当前`Worker`进程的操作系统进程`ID`。与`posix_getpid()`的返回值相同。

```php
Swoole\Server->worker_pid: int
```

### $taskworker

当前进程是否是 `Task` 进程。

```php
Swoole\Server->taskworker: bool
```

  * **返回值**

    * `true`表示当前的进程是`Task`工作进程
    * `false`表示当前的进程是`Worker`进程

### $connections

`TCP`连接迭代器，可以使用`foreach`遍历服务器当前所有的连接，此属性的功能与[Server->getClientList](/server/methods?id=getclientlist)是一致的，但是更加友好。

遍历的元素为单个连接的`fd`。

```php
Swoole\Server->connections
```

!> `$connections`属性是一个迭代器对象，不是PHP数组，所以不能用`var_dump`或者数组下标来访问，只能通过`foreach`进行遍历操作

  * **Base 模式**

    * [SWOOLE_BASE](/learn?id=swoole_base) 模式下不支持跨进程操作`TCP`连接，因此在`BASE`模式中，只能在当前进程内使用`$connections`迭代器

  * **示例**

```php
foreach ($server->connections as $fd) {
  var_dump($fd);
}
echo "当前服务器共有 " . count($server->connections) . " 个连接\n";
```

### $ports

监听端口数组，如果服务器监听了多个端口可以遍历`Server::$ports`得到所有`Swoole\Server\Port`对象。

其中`swoole_server::$ports[0]`为构造方法所设置的主服务器端口。

  * **示例**

```php
$ports = $server->ports;
$ports[0]->set($settings);
$ports[1]->on('Receive', function () {
    //callback
});
```