<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
		'open_http_protocol' => true,
		'worker_num' => 1,
		'dispatch_mode' => 1,
		'package_max_length' => 1024 * 1024 * 2,
));

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	echo "recv: ".strlen($data)."\n";
});

$serv->start();