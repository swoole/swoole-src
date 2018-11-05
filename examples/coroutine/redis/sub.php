<?php
go(function () {


$redis = new Swoole\Coroutine\Redis();
$redis->connect('127.0.0.1', 6379);
//while (true) 
{
	$msg = $redis->subscribe(array("msg_1"));
	var_dump($msg);
}

});
