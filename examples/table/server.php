<?php 
$table = new swoole_table(1024);
$table->column('fd', swoole_table::TYPE_INT);
$table->column('from_id', swoole_table::TYPE_INT);
$table->column('data', swoole_table::TYPE_STRING, 64);
$table->create();

$serv = new swoole_server('127.0.0.1', 9501);
$serv->set(['dispatch_mode' => 1]);
$serv->table = $table;

$serv->on('connect', function($serv, $fd, $from_id){
	$info = $serv->connection_info($fd);
	$serv->send($fd, "INFO: fd=$fd, from_id=$from_id, addr={$info['remote_ip']}:{$info['remote_port']}\n");
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	
	$cmd = explode(" ", trim($data));
	
	//get
	if ($cmd[0] == 'get')
	{
		//get self
		if (count($cmd) < 2) 
		{
			$cmd[1] = $fd;
		}
		$get_fd = intval($cmd[1]);
		$info = $serv->table->get($get_fd);
		$serv->send($fd, var_export($info, true)."\n");
	}
	//set
	elseif ($cmd[0] == 'set')
	{
		$ret = $serv->table->set($fd, array('from_id' => $data, 'fd' => $fd, 'data' => $cmd[1]));
		if ($ret === false) 
		{
			$serv->send($fd, "ERROR\n");
		}
		else
		{
			$serv->send($fd, "OK\n");
		}
	}
	else 
	{
		$serv->send($fd, "command error.\n");
	}
});

$serv->start();