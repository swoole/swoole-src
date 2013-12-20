Swoole
=====
PHP's asynchronous & concurrent & distributed networking framework.

* Event-driven
* Full asynchronous non-blocking
* Multi-Thread or Multi-Process
* Millisecond timer
* Asynchronous MySQL
* AsyncTask workers


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


