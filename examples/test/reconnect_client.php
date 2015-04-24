<?php

class ReconnectClient
{
    /**
     * @var swoole_client
     */
    protected $swoole_client;
    protected $timer;
    protected $host;
    protected $port;

    public $timeout = 1000; //1秒

    function connect($host, $port)
    {
        if (empty($this->host))
        {
            $this->host = $host;
            $this->port = $port;
        }

        $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $client->on("connect", [$this, 'onConnect']);
        $client->on("receive", function(swoole_client $cli, $data){
            $cli->send("HELLO");
            echo "recv from server: $data\n";
            usleep(100000);
        });
        $client->on("error", [$this, 'onError']);
        $client->on("close", [$this, 'onClose']);
        $client->connect($host, $port);
        $this->timer = swoole_timer_after($this->timeout, [$this, 'onConnectTimeout']);
        $this->swoole_client = $client;
    }

    function onClose(swoole_client $cli)
    {
        echo "connection[$cli->sock] close\n";
        $this->connect($this->host, $this->port);
    }

    function onError(swoole_client $cli)
    {
        unset($this->swoole_client);
        echo "connection error\n";
    }

    function onConnect(swoole_client $cli)
    {
        swoole_timer_clear($this->timer);
        $cli->send("HELLO\n");
    }

    function onConnectTimeout()
    {
        echo "socket timeout\n";
        $this->swoole_client->close();
    }
}

$client = new ReconnectClient;
$client->connect('127.0.0.1', 9501);
echo "connect to 127.0.0.1:9501\n";
//for PHP5.3-
//swoole_event_wait();
