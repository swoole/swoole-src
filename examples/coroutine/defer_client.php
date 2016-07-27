<?php
/* new multi implement test */
$server = new Swoole\Http\Server("127.0.0.1", 9502, SWOOLE_BASE);

$server->set([
	'worker_num' => 1,
]);

$server->on('Request', function ($request, $response) {
	$redis = new Swoole\Coroutine\Redis();
	$res = $redis->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$redis->setDefer(true);
	$redis->get('key');
	$res = $redis->get('key');//get false
	var_dump($res);

	var_dump($redis->setDefer());//get true
	var_dump($redis->setDefer(false));//get false

	//穿插其他client也能正常工作
	$redis_tmp = new Swoole\Coroutine\Redis();
	$res = $redis_tmp->connect('127.0.0.1', 6379);
	if ($res == false) {
		$response->end("Redis connect fail!");
		return;
	}
	$res = $redis_tmp->set('key_tmp', 'HaHa');//get true
	var_dump($res);


	$http_client= new Swoole\Coroutine\Http\Client('km.oa.com', 80);
	$http_client->setDefer();
	$http_client->get('/');

	$mysql = new Swoole\Coroutine\MySQL();
	$res = $mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
	if ($res == false) {
		$response->end("MySQL connect fail!");
		return;
	}
	$mysql->setDefer(true);
	$mysql->query('select sleep(1)', 2);

	$udp = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $res = $udp->connect("127.0.0.1", 9906, 2);
	$udp->send('Hello World!');

	//穿插其他client也能正常工作
	$udp_tmp = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $res = $udp_tmp->connect("127.0.0.1", 9909, 2);//nonexistent server
	$res = $udp_tmp->recv();//get false with timeout
	var_dump($res);

	$udp_res = $udp->recv();
	$res = $mysql->query('select sleep(1)', 2);//get false
	var_dump($res);
	$res = $mysql->setDefer(false);
	var_dump($res);//get false
	$res = $mysql->setDefer();
	var_dump($res);//get true
	$mysql_res = $mysql->recv();
	$res = $redis->get('key');//get false
	var_dump($res);
	$redis_res = $redis->recv();
	$res = $http_client->get('/');
	var_dump($res);//get false
	$res = $http_client->recv();
	var_dump($res);//get true

	var_dump($udp_res, $mysql_res, $redis_res, $http_client);
	var_dump($http_client->setDefer(false));
	var_dump($mysql->getDefer(), $redis->getDefer(), $http_client->getDefer());
	$response->end('Test End');
});
$server->start();
