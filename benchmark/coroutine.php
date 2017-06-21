<?php
class Server
{
    public $server;
    public $redisPool = [];
    public $mysqlPool = [];

    public function run()
    {
        $this->server = new Swoole\Http\Server("0.0.0.0", 9501, SWOOLE_BASE);
        $this->server->set([
            'worker_num' => 1,
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
//        $redis = new Swoole\Coroutine\Redis();
//        $redis->connect('127.0.0.1', 6379);
//        $this->redisPool[$fd] = $redis;
    }

    public function onClose($serv, $fd, $reactorId)
    {
//        $this->log("onClose: fd=$fd");
//        $redis = $this->redisPool[$fd];
//        $redis->close();
//        unset($this->redisPool[$fd]);
    }

    public function onRequest($request, $response)
    {
//        $this->log("onRequest: fd=$request->fd");

        if (empty($this->redisPool[$request->fd]))
        {
            $redis = new Swoole\Coroutine\Redis();
            $redis->connect('127.0.0.1', 6379);
            $this->redisPool[$request->fd] = $redis;
        }
        else
        {
            $redis = $this->redisPool[$request->fd];
        }
        $ret = $redis->get('key');

        if (empty($this->mysqlPool[$request->fd]))
        {
            $mysql = new Swoole\Coroutine\MySQL();
            $mysql->connect([
                'host' => '127.0.0.1',
                'port' => 3306,
                'user' => 'root',
                'password' => 'root',
                'database' => 'test',
            ]);
        }
        else
        {
            $mysql = $this->mysqlPool[$request->fd];
        }

        $ret2 = $mysql->query('show tables');
        $response->end('redis value=' . $ret.', mysql talbes='.var_export($ret2, true));
    }
}

$server = new Server();
$server->run();



