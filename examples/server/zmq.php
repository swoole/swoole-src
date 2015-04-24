<?php
$serv = new swoole_server("0.0.0.0", 9501);

$context = new ZMQContext();
    
$sender = new ZMQSocket($context, ZMQ::SOCKET_PUSH);
$sender->bind("tcp://*:5557");
    
$receiver = new ZMQSocket($context, ZMQ::SOCKET_PULL);
$receiver->bind("tcp://*:5558");
    
function onZMQR()
{
	global $receiver;
	$string = $receiver->recv();
	echo $string, PHP_EOL;
}

$serv->set(array(
	//'tcp_defer_accept' => 5,
	'worker_num' => 1,
	'reactor_num' => 1,
	//'daemonize' => true,
	//'log_file' => '/tmp/swoole.log'
));

$serv->on('workerStart', function($serv, $worker_id) {
	global $sender;
    global $receiver;
    
    $rfd = $receiver->getsockopt(ZMQ::SOCKOPT_FD);  
    swoole_event_add($rfd, 'onZMQR', NULL , SWOOLE_EVENT_READ);
    echo "worker start\n";
});

$serv->on('connect', function ($serv, $fd, $from_id){
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Connect.\n";
});

$serv->on('receive', function (swoole_server $serv, $fd, $from_id, $data) {
	
    $cmd = trim($data);
    echo "[#".posix_getpid()."]\tClient[$fd]: $data\n";
    
    if($cmd == "zmqtest")
    {
        echo 'aaaaaaaaaaaa'. PHP_EOL;
        $sender->send("msg to zmq");
    }
    $serv->send($fd, 'OK'.PHP_EOL);
    //$serv->close($fd);
});

$serv->on('close', function ($serv, $fd, $from_id) {
    echo "[#".posix_getpid()."]\tClient@[$fd:$from_id]: Close.\n";
});

//$serv->start();
