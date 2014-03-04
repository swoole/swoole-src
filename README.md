Swoole
=====
PHP's asynchronous & concurrent & distributed networking framework.

* Event-driven
* Full asynchronous non-blocking
* Multi-Thread or Multi-Process
* Millisecond timer
* Asynchronous MySQL
* AsyncTask workers
* Linux native aio

Install
-----
```
pecl install swoole
```


Example
-----

__Server__
```php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->on('connect', function ($serv, $fd){
 	echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	$serv->send($fd, 'Swoole: '.$data);
    $serv->close($fd);
});
$serv->on('close', function ($serv, $fd) {
 	echo "Client: Close.\n";
});
$serv->start();
```
__Client__
```php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$client->on("connect", function($cli) {
    $cli->send("hello world\n");
});

$client->on("receive", function($cli, $data){
    echo "Receive: $data\n";
});

$client->on("error", function($cli){
    echo "connect fail\n";
});

$client->on("close", function($cli){
    echo "close\n";
});

$client->connect('127.0.0.1', 9501, 0.5);
```
__Event__
```php
$fp = stream_socket_client("tcp://127.0.0.1:9501", $errno, $errstr, 30);
if (!$fp) {
    exit("$errstr ($errno)\n");
}
fwrite($fp, "HELLO world");
swoole_event_add($fp, function($fp){
	echo fgets($fp, 1024);
	swoole_event_del($fp);
    fclose($fp);
});
```

__Task__
```php
$serv = new swoole_server("127.0.0.1", 9502);
$serv->set(array('task_worker_num' => 4));
$serv->on('Receive', function($serv, $fd, $from_id, $data) {
    $task_id = $serv->task("Async");
    echo "Dispath AsyncTask: id=$task_id\n";
});
$serv->on('Task', function ($serv, $task_id, $from_id, $data) {
    echo "New AsyncTask[id=$task_id]".PHP_EOL;
    $serv->finish("$data -> OK");
});
$serv->on('Finish', function ($serv, $task_id, $data) {
    echo "AsyncTask[$task_id] Finish: $data".PHP_EOL;
});
$serv->start();
```

__Timer__

```php
swoole_timer_add(1000, function($interval) {
    echo "timer[$interval] call\n";
});

swoole_timer_add(2000, function($interval) {
    echo "timer[$interval] call\n";
    swoole_timer_del(2000);
});
```

__Files__
* PHP: [examples/server.php](examples/server.php)
* C/C++: [examples/server.c](examples/server.c)
* Client: [examples/client.php](examples/client.php)

Developer Mail-List
-----
* Google Group: <https://groups.google.com/forum/#!forum/swoole>  
* Email: <swoole@googlegroups.com>


For PHP
-----
```shell
cd swoole/
phpize
./configure
make && make install
```

For C/C++
-----
```shell
cd swoole/
cmake .
make && make install
```

PHP Application Server
-----
https://github.com/matyhtf/swoole_framework


Document
----
* [Document 中文](http://www.swoole.com/wiki/index/) 
* Document English. Wait moment.

License
-----
Apache License Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0.html>


