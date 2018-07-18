<?php
ini_set("memory_limit","512M");
use Swoole\Coroutine as co;
class Server
{
    public $server;
    public $redisPool = [];
    public $chan;
    
    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9502, SWOOLE_BASE);
        $this->server->set([
            'worker_num' => 1,
        ]);
        $this->chan = new  Swoole\Coroutine\Channel(5);

        // $this->server->on('Connect', [$this, 'onConnect']);
        $this->server->on('Request', [$this, 'onRequest']);
//         $this->server->on('Close', [$this, 'onClose']);
        $this->server->on('WorkerStart', function ($serv, $worker_id){
            for ($i = 0; $i < 4; $i ++) {
                $this->chan->push(1);
            }
        });
        $this->server->set(['trace_flags' => 1 << 15, 'log_level' => 0]);
        $this->server->start();
    }


    public function onRequest($request, $response)
    {
        $fd = $request->fd;
        $data = $this->chan->pop();
        co::create(function () {
            co::sleep(1);
        });
        $this->chan->push($data);
        $response->end($data);
    }
}

$server = new Server();
Swoole\Coroutine::set(array(
    'max_coroutine' => 1000,
));
$server->run();
