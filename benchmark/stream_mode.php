<?php
class Server
{
    public $server;
    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9501);
        $this->server->set([
            'worker_num' => 1,
            'dispatch_mode' => 7
        ]);

//        $this->server->on('Connect', [$this, 'onConnect']);
        $this->server->on('Request', [$this, 'onRequest']);
//        $this->server->on('Close', [$this, 'onClose']);

        $this->server->start();
    }

    function log($msg)
    {
        echo $msg."\n";
    }

    public function onConnect($serv, $fd, $reactorId)
    {
//        $this->log("onConnect: fd=$fd");
    }

    public function onClose($serv, $fd, $reactorId)
    {
//        $this->log("onClose: fd=$fd");
    }

    public function onRequest($request, $response)
    {
        $response->end("data:".str_repeat('A', rand(100, 200)));
    }
}

$server = new Server();
$server->run();
