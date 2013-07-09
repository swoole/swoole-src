php_swoole
==========

A Swoole entirely written in C language, based on the Linux epoll does not rely on any third-party libraries, as a the PHP extensions running high-performance network server framework, you can easily maintain more than 100,000 concurrent TCP connections. Swoole provides a full asynchronous, non-blocking, parallel PHP Socket Server to achieve. Support UDP, TCP, IPv6 support multi-port monitoring, multi timer and operation mode can be configured.
PHP developers do not care about the underlying implementation, only need to use PHP to write the callback function, write the business logic code can be. The network can be used for server-side development, such as WebSocket Server, Web server, FTP server.

feature
-----

* Event-driven
* Full asynchronous non-blocking
* No lock design
* Separate read and write
* Concurrent execution. Support Multi-Thread or Multi-Process
* Support IPv6

blog
-----
http://swoole.sinaapp.com/ 中文(Chinese)

example
-----
server.php
```php
<?php
$serv = swoole_server_create("127.0.0.1", 9500, SWOOLE_THREAD, SWOOLE_SOCK_TCP);

swoole_server_set($serv, array(
    'timeout' => 2.5,  //select and epoll_wait timeout. 
    'poll_thread_num' => 2, //reactor thread num
    'writer_num' => 2,     //writer thread num
    'worker_num' => 4,    //worker process num
    'backlog' => 128,   //listen backlog
));

/*
argv0  server resource
argv1  listen host
argv2  listen port
argv3  sock_type  SWOOLE_SOCK_TCP or SWOOLE_SOCK_TCP6 or SWOOLE_SOCK_UDP or SWOOLE_SOCK_UDP6
*/
swoole_server_addlisten($serv, "127.0.0.1", 9501, SWOOLE_SOCK_UDP);
function my_onStart($serv)
{
    echo "Server：start\n";
}

function my_onShutdown($serv)
{
    echo "Server：onShutdown\n";
}

function my_onTimer($serv, $interval)
{
    echo "Server：Timer Call.Interval=$interval \n";
}

function my_onClose($serv,$fd,$from_id)
{
	echo "Client：Close. fd=$fd|from_id=$from_id\n";
}

function my_onConnect($serv,$fd,$from_id)
{
	echo "Client：Connect. fd=$fd|from_id=$from_id\n";
}

function my_onReceive($serv, $fd, $from_id, $data)
{
	echo "Client：Data. fd=$fd|from_id=$from_id|data=$data\n";
	swoole_server_send($serv, $fd, "Server: $data");
	//swoole_server_send($serv, $other_fd, "Server: $data", $other_from_id);
	//swoole_server_close($serv, $fd, $from_id);
	//swoole_server_close($serv, $ohter_fd, $other_from_id);
}

swoole_server_handler($serv, 'onStart', 'my_onStart');
swoole_server_handler($serv, 'onConnect', 'my_onConnect');
swoole_server_handler($serv, 'onReceive', 'my_onReceive');
swoole_server_handler($serv, 'onClose', 'my_onClose');
swoole_server_handler($serv, 'onShutdown', 'my_onShutdown');
swoole_server_handler($serv, 'onTimer', 'my_onTimer');
swoole_server_addtimer($serv, 2);
swoole_server_addtimer($serv, 10);
swoole_server_start($serv);
?>
```
client.php
```php
<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC); //同步阻塞
$client->connect('127.0.0.1', 9500, 0.5, 0);
for($i=0; $i &lt; 1000; $i++){
    $client-&gt;send("hello world-{$i}");
    $data = $client-&gt;recv(1024, 0);
    echo $data;
}
$client->close();
```

```sh
php server.php

telnet 127.0.0.1 9500
hello
server: hello
```

