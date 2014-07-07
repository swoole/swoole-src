<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
		'open_length_check'     => 1,
		'dispatch_mode'         => 1,
		'worker_num'            => 4,
		'package_length_type'   => 'N',
		'package_length_offset' => 4,       //第N个字节是包长度的值
		'package_body_offset'   => 8,       //第几个字节开始计算长度
		'package_max_length'    => 200000,  //协议最大长度
));
$serv->on('connect', function ($serv, $fd){
	echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	//$protocol = unpack('s*', $data);
	$output = '>> ';
	echo ">> received length=".strlen($data)."\n";
// 	foreach ($protocol as $k=>$v) {
// 		$output .= sprintf('%d,', $v);
// 	}
// 	echo $output . "\n";
	//$serv->send($fd, 'Swoole: '.$data);
	//$serv->close($fd);
});
$serv->on('close', function ($serv, $fd) {
	echo "Client: Close.\n";
});
$serv->start();
