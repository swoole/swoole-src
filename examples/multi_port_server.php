<?php
$serv = new swoole_server("0.0.0.0", 9501);
//这里监听了一个UDP端口用来做内网管理
$serv->addlistener('127.0.0.1', 9502, SWOOLE_SOCK_UDP);
$serv->on('connect', function ($serv, $fd) {
    echo "Client:Connect.\n";
});
$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    $info = $serv->connection_info($fd, $from_id);
    //来自9502的内网管理端口
    if($info['server_port'] == 9502) {
		$serv->send($fd, "welcome admin\n");
		$start_fd = 0;
        while(true)
        {
            $conn_list = $serv->connection_list($start_fd, 10);
            if($conn_list === false)
            {
                break;
            }
            $start_fd = end($conn_list);
            var_dump($conn_list);
            
            foreach($conn_list as $conn)
            {
                if($conn === $fd) continue;
                $serv->send($conn, "hello from $fd\n");
            }
        }
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
