Swoole
=====
[![Build Status](https://api.travis-ci.org/matyhtf/swoole.svg)](https://travis-ci.org/matyhtf/swoole)

PHP's asynchronous & concurrent & distributed networking framework.

* event-driven
* full asynchronous non-blocking
* multi-thread reactor
* multi-process worker
* millisecond timer
* async MySQL
* async task
* async read/write file system
* async dns lookup
* support IPv4/IPv6/UnixSocket/TCP/UDP

Install
-----
```
pecl install swoole
```


Example
-----

__server__
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
__client__
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
__event__
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

__async mysql__
```php
$db = new mysqli;
$db->connect('127.0.0.1', 'root', 'root', 'test');
$db->query("show tables", MYSQLI_ASYNC);
swoole_event_add(swoole_get_mysqli_sock($db), function($__db_sock) {
    global $db;
    $res = $db->reap_async_query();
    var_dump($res->fetch_all(MYSQLI_ASSOC));
    exit;
});
```

__async task__
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

__timer__

```php
swoole_timer_add(1000, function($interval) {
    echo "timer[$interval] call\n";
});

swoole_timer_add(2000, function($interval) {
    echo "timer[$interval] call\n";
    swoole_timer_del(2000);
});
```

__async_io__
```php
swoole_async_readfile(__DIR__.'/server.php', function($filename, $content){
    echo "file: $filename\ncontent-length: ".strlen($content)."\nContent:\n";
    echo $content;
    swoole_async_writefile('copy.php', $content, function($file, $ret) {
        echo "file: $file\n";
        swoole_event_exit();
	});
});
```
__dns_lookup__
```php
swoole_async_dns_lookup("www.google.com", function($host, $ip){
    echo "$host : $ip\n";
});
```

__Files__
* PHP: [examples/server.php](examples/server.php)
* C/C++: [examples/server.c](examples/server.c)
* Client: [examples/client.php](examples/client.php)

Document
----
* [Document 中文](http://www.swoole.com/wiki/index/) 
* [Document English](https://github.com/matyhtf/swoole_doc/blob/master/docs/en/index.md) 

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


License
-----
Apache License Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0.html>


