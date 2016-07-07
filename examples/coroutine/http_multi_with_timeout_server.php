<?php
class Server
{
    public $server;

    public function run()
    {
        $this->server = new swoole_http_server("127.0.0.1", 9502, SWOOLE_BASE);
        $this->server->set([
            'worker_num' => 1,
        ]);
        $this->server->on('Request',['Server', 'onRequest']);
        $this->server->start();
    }

    public static function onRequest($request, $response)
    {
		$multi = new swoole_multi();
		$swoole_mysql = new swoole_mysql_coro();
		$ret = $swoole_mysql->connect(['host' => '192.168.244.128', 'user' => 'mha_manager', 'password' => 'mhapass', 'database' => 'tt']);
		$redis = new swoole_redis_coro();
		$redis->connect('127.0.0.1', 6379);
		$redis2 = new swoole_redis_coro();
		$redis2->connect('127.0.0.1', 6379);
		$redis3 = new swoole_redis_coro();
		$redis3->connect('127.0.0.1', 6379);
        $cli = new swoole_client_coro(SWOOLE_SOCK_TCP);
        $ret = $cli->connect("127.0.0.1", 8888);
        $udp_cli = new swoole_client_coro(SWOOLE_SOCK_UDP);
        $ret = $udp_cli->connect("127.0.0.1", 8888);
		$multi->add(['udp' => $udp_cli, 'tcp' => $cli, 'ttttttt' => $swoole_mysql, 'test' => $redis, 'test2' => $redis2, 'test3' => $redis3]);
        $ret = $cli->send("hello world in object");
		$cli->recv();
		var_dump($ret);
        $ret = $udp_cli->send("hello world in object");
		var_dump($ret);
		$ret = $swoole_mysql->query('select sleep(1)', 2000);
		var_dump($ret, $swoole_mysql);
		$redis->get('key');
		$ret = $redis->get('key');
		var_dump($ret, $redis);
		$redis2->set('test_key', 'haha');
		$ret = $redis3->multi()->get('tt')->set('tt', 'ffff')->get('tt')->del('tt')->exec();
		$ret = $multi->recv();
		var_dump($ret, $swoole_mysql);
		$redis->close();
		$redis2->close();
		$redis3->close();
		$cli->close();
		$udp_cli->close();
		$ret = $swoole_mysql->close();
		$response->end('Test End');
    }
}

$server = new Server();

$server->run();
