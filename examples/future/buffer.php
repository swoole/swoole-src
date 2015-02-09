<?php
$serv = new swoole_server("0.0.0.0", 9501);
$serv->set(array(
	//'tcp_defer_accept' => 5,
	'worker_num' => 1,
	//'daemonize' => true,
	//'log_file' => '/tmp/swoole.log'
));
$serv->on('timer', function($serv, $interval) {
	echo "onTimer: $interval\n";
});
$serv->on('workerStart', function($serv, $worker_id) {
	//if($worker_id == 0) $serv->addtimer(500);
});
$serv->on('connect', function ($serv, $fd, $from_id){
    //echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});

$serv->on('BufferInput', function($serv, $fd, $from_id, $data) {
	$buffer = $serv->get_buffer($fd);
	
	//buffer不存在
	if (!$buffer) 
	{
		$buffer = new swoole_buffer;
		$serv->set_buffer($fd, $buffer);
	}
		
	//等待所有数据，将不会再通知
	$buffer->wait($size);
	
	//写入到buffer中
	$buffer->write($data);
	
	//从缓存区中读取数据
	$buffer->read(8192, 0);
	
	//清空数据
	$buffer->clear();

	//释放此buffer内存
	$buffer->free();
	
	//缓存区长度
	$buffer->length();
	
	//投递此数据到worker进程，并清理此buffer
	$serv->dispatch($buffer, $worker_id);
	
	$serv->send($fd, "hello world");
	$serv->close($fd);	
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
    //echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    $serv->send($fd, json_encode(array("hello" => '1213', "bat" => "ab")));
    //$serv->close($fd);
});
$serv->on('close', function ($serv, $fd, $from_id) {
    //echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});
$serv->start();