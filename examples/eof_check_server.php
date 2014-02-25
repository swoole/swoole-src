<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
	'worker_num' => 1,
	'reactor_num' => 1,
    'open_eof_check'  => 1,
    'package_eof'   => "\r\n\r\n",
    'package_max_length' => 8192 * 2,
));
$serv->on('connect', function ($serv, $fd){
    echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
    echo "receive|package_length=".strlen($data).PHP_EOL;
    $serv->send($fd, 'Swoole: '.$data);
});
$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});
$serv->start();
