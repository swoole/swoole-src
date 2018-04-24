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

        // $this->server->on('Connect', [$this, 'onConnect']);
        $this->server->on('Request', [$this, 'onRequest']);
        $this->server->on('Close', [$this, 'onClose']);
        $this->server->set(['trace_flags' => 1 << 15, 'log_level' => 0]);
        $this->server->start();
    }


    // public function onConnect($serv, $fd, $reactorId)
    // {
    //     echo "onConnect $fd\n";
    // }


    public function onClose($serv, $fd, $reactorId)
    {
        $cid = co::getUid();
        echo "onClose $cid $fd\n";
    }


    public function onRequest($request, $response)
    {
        $fd = $request->fd;
        // co::create(function () use ($fd,$response) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
            $res = $client->connect('127.0.0.1', 9501, 1);
            co::sleep(1);
            $cid = co::getUid();
            echo "fd:$fd  cid:$cid  co resume : connect ret = ".var_export($res,1)."\n";
            $response->end(111);
        // });
    }
}

$server = new Server();

$server->run();
