<?php
swoole_load_module(__DIR__.'/test.so');
swoole_load_module(dirname(__DIR__).'/c_module/test.so');

$serv = new swoole_server("0.0.0.0", 9502, SWOOLE_BASE);
//$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(array(
    'worker_num' => 1,
    'open_length_check' => true,
    'package_length_func' => 'test_get_length',
));


$serv->on('connect', function (swoole_server $serv, $fd, $from_id) {
	//echo "connect\n";;
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {	
	$serv->send($fd, "Swoole: ".$data);
	//$serv->close($fd);
});


$serv->start();
