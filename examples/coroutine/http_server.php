<?php
use Swoole\Coroutine as co;
class Server
{
    public $server;
    public $redisPool = [];

    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9502);
        $this->server->set([
            'worker_num' => 1,
        ]);

        $this->server->on('Connect', [$this, 'onConnect']);
        $this->server->on('Request', [$this, 'onRequest']);
        $this->server->on('Close', [$this, 'onClose']);
        $this->server->set(['trace_flags' => 1 << 15, 'log_level' => 1]);
        $this->server->start();
    }


    public function onConnect($serv, $fd, $reactorId)
    {
        echo "connect res\n";
    }


    public function onClose($serv, $fd, $reactorId)
    {

    echo "onClose \n";

    }


    public function onRequest($request, $response)
    {
//         co::create(function () use ($response) {
            $redis = new Swoole\Coroutine\Redis();
            $redis->connect('127.0.0.1', 6379);
            $data = $redis->get("key");
            var_dump($data);
            Swoole\Coroutine::sleep(1);
            $response->end($data);            
            $redis->close();
//         });
    }
}

$server = new Server();

$server->run();



