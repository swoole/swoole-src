Swoole
=====
Asynchronous & Concurrent & Distributed with PHP.
PHP的异步、并行、分布式框架

* [Document 中文](http://www.swoole.com/wiki/index/) 
* Document English. Wait supplement

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

$client->on("receive", function($cli){
    $data = $cli->recv();
    echo "Receive: $data\n";
});

$client->on("error", function($cli){
    echo "connect fail\n";
});

$client->on("close", function($cli){
    echo "close\n";
    $cli->close();
});

$client->connect('127.0.0.1', 9501, 0.5);
```

Features
-----

* Event-driven
* Full asynchronous non-blocking
* No lock design
* Separate read and write
* Concurrent execution. Support Multi-Thread or Multi-Process
* Support IPv6

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

Example
-----
* PHP: [examples/server.php](examples/server.php)
* C/C++: [examples/server.c](examples/server.c)
* Client: [examples/client.php](examples/client.php)

License
-----
Apache License Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0.html>



