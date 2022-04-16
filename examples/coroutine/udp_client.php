<?php
class Client
{
    private $ip = "127.0.0.1";
    const PORT = 8888;
    private $data;

    public function sendRequest()
    {
        $this->data = "swoole test";
        $this->send();
        $this->moreThanOneRecv();
        return $ret;
    }

    public function send()
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $ret = $cli->connect($this->ip, self::PORT);
        $cli->send($this->data);
        $ret = $cli->recv();
        $cli->close();
    }

    public function moreThanOneRecv()
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $ret = $cli->connect($this->ip, self::PORT);
        $cli->send("sent by cli");

        $cli2 = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $ret = $cli2->connect($this->ip, self::PORT);
        $cli2->send("sent by cli2");

        $cli3 = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $ret = $cli3->connect($this->ip, self::PORT);
        $cli3->send("sent by cli3");

        sleep(1);
        $ret = $cli3->recv();
        $ret = $cli2->recv();
        $ret = $cli->recv();
        return;
    }
}

class Server
{
    public $server;

    public function run()
    {
        $this->server = new Swoole\Http\Server("127.0.0.1", 9502);
        $this->server->set([
            'worker_num' => 1,
            'daemonize' => true,
            'log_file' => '/tmp/swoole.log',
        ]);
        $this->server->on('Request',['Server', 'onRequest']);
        $this->server->start();
    }

    public static function onRequest($request, $response)
    {
        self::staticFunc();
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
        $client = new Client();
        $ret = $client->sendRequest();
        $response->end($ret);
    }
}

$server = new Server();
$server->run();
