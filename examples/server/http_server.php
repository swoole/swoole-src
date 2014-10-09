<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
		'open_http_protocol' => true,
		'worker_num' => 1,
		'dispatch_mode' => 2,
		'package_max_length' => 1024 * 1024 * 2,
));

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "recv: ".strlen($data)."\n";
	$body = "<h1>hello world!</h1>";
	$header  = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Keep-Alive\r\n";
	$header .= "Content-Length: ".strlen($body)."\r\n\r\n";
	$serv->send($fd, $header.$body);
});

$serv->start();