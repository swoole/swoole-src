<?php
$serv = new swoole_server("0.0.0.0", 9501);
//这里监听了一个UDP端口用来做内网管理
$serv->addlistener('127.0.0.1', 9502, SWOOLE_SOCK_UDP);
$serv->on('connect', function ($serv, $fd) {
    echo "Client:Connect.\n";
});
$serv->on('receive', function ($serv, $fd, $from_id, $data) {
    $info = $serv->connection_info($fd, $from_id);
    //来自9502的内网管理端口
    if($info['from_port'] == 9502) {
		$serv->send($fd, "welcome admin\n");
	}
	//来自外网
	else {
		$serv->send($fd, 'Swoole: '.$data);
	}
});
$serv->on('close', function ($serv, $fd) {
    echo "Client: Close.\n";
});
$serv->start();
