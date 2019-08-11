<?php
go(function () {
	$redis = new Swoole\Coroutine\Redis();
	$redis->connect('127.0.0.1', 6379);
	$msg = $redis->subscribe(array("msg_1"));
	while ($msg = $redis->recv()) 
	{
		var_dump($msg);
	}
});

go(function () {
	$redis = new Swoole\Coroutine\Redis();
	$redis->connect('127.0.0.1', 6379);
	$msg = $redis->subscribe(array("msg_2"));
	while ($msg = $redis->recv()) 
	{
		var_dump($msg);
	}
});
