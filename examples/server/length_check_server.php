<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
		'open_length_check'     => 1,
		'dispatch_mode'         => 1,
		'worker_num'            => 4,
		'package_length_type'   => 'N',
		'package_length_offset' => 0,       //第N个字节是包长度的值
		'package_body_offset'   => 4,       //第几个字节开始计算长度
		'package_max_length'    => 2000000,  //协议最大长度
));

$serv->on('connect', function ($serv, $fd){
	echo "Client:Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    $req = unserialize(substr($data, 4));
	echo "#{$serv->worker_id}>> received length=".strlen($data).", SerId: {$req['int1']}\n";
	$serv->send($fd, $data);
});

$serv->on('close', function ($serv, $fd) {
	echo "Client: Close.\n";
});
$serv->start();
