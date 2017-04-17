<?php
swoole_load_module(__DIR__.'/test.so');

$serv = new swoole_server("0.0.0.0", 9502);
//$serv = new swoole_server("0.0.0.0", 9502);
$serv->set(array(
    'worker_num' => 4,
    'dispatch_func' => 'my_dispatch_function',
));

$serv->on('connect', function (swoole_server $serv, $fd, $from_id) {
	//echo "connect\n";;
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
  var_dump($data, $fd, $serv->worker_id);
});


$serv->start();
