<?php

class BigSizeMemory
{
    private $host;
    private $port;
    private $data;
    private $tcpClient;
    private $httpClient;

    public function __construct($host = "11.11.11.11", $port = 9000)
    {
        $this->data = str_repeat("\0", 1024 * 1024); // 1M
        $this->host = $host;
        $this->port = $port;
    }

    function swoole_client_memory_leak()
    {
        $obj = new BigSizeMemory();
        $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $obj->cli = $cli;
        $cli->on("connect", function(swoole_client $cli) {
            assert(false);
        });
        $cli->on("receive", function(swoole_client $cli, $data) {
            assert(false);
        });
        $cli->on("error", function(swoole_client $cli) { echo "error\n"; unset($this->data); });
        $cli->on("close", function(swoole_client $cli) { echo "close\n"; unset($this->data); });

        $cli->connect($this->host, $this->port);
        $this->tcpClient = $cli;
    }

    function swoole_http_client_memory_leak()
    {
        $cli = new swoole_http_client($this->host, $this->port);
        $cli->on('close', function($cli) { echo "error\n"; unset($this->data); });
        $cli->on('error', function($cli) { echo "close\n"; unset($this->data); });
        $cli->get('/', function(swoole_http_client $cli) {});
        $this->httpClient = $cli;
    }
}





// 回调不触发, 对象不析构, 内存泄漏
(new BigSizeMemory())->swoole_http_client_memory_leak();
(new BigSizeMemory())->swoole_client_memory_leak();