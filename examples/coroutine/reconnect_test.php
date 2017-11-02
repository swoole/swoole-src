<?php
/* new multi implement test */
$server = new Swoole\Http\Server("127.0.0.1", 9502, SWOOLE_BASE);

$server->set([
	'worker_num' => 1,
]);

$server->on('Request', function ($request, $response) {

	/*
	$mysql = new Swoole\Coroutine\MySQL();
	$res = $mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
	if ($res == false) {
		$response->end("MySQL connect fail!");
		return;
	}
	$res = $mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
	if ($res == false) {
		$response->end("MySQL connect fail!");
		return;
	}
	$mysql->close();
	
	$res = $mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
	if ($res == false) {
		$response->end("MySQL connect fail!");
		return;
	}
	$res = $mysql->query('select sleep(1)', 2);
	var_dump($res);

	$res = $mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
	if ($res == false) {
		$response->end("MySQL connect fail!");
		return;
	}
	$res = $mysql->query('select sleep(1)', 2);
	var_dump($res);
	*/

	$redis = new Swoole\Coroutine\Redis();
	$res = $redis->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$res = $redis->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$redis->close();
	$res = $redis->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$res = $redis->get('key');
	var_dump($res);
	$res = $redis->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$res = $redis->get('key');
	var_dump($res);

	$response->end('Test End');
});
$server->start();
