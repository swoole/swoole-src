<?php
class Server
{
    public $server;
    public $redisPool = [];

    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9501, SWOOLE_BASE);
        $this->server->set([
            'worker_num' => 1,
        ]);

        $this->server->on('Connect', [$this, 'onConnect']);
        $this->server->on('Request', [$this, 'onRequest']);
        $this->server->on('Close', [$this, 'onClose']);

        $this->server->start();
    }


    public function onConnect($serv, $fd, $reactorId)
    {
		$redis = new Swoole\Coroutine\Redis();
		$redis->connect('127.0.0.1', 6379);
        $this->redisPool[$fd] = $redis;
    }


    public function onClose($serv, $fd, $reactorId)
    {
        $redis = $this->redisPool[$fd];
        $redis->close();
        unset($this->redisPool[$fd]);
    }


    public function onRequest($request, $response)
    {
		$redis = $this->redisPool[$request->fd];
		$ret = $redis->get('key');
		var_dump($ret, $redis);
        $response->end('xxxx');
    }
}

$server = new Server();

$server->run();



