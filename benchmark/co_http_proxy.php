<?php

class Co_Http_ProxyServer
{
    protected $backend_server = ['host' => '127.0.0.1', 'port' => 80];
    protected $serv;

    function run()
    {
        Co::set(['enable_reuse_port' => true]);
        $serv = new Swoole\Http\Server("127.0.0.1", 9509);
        $serv->set(array(
            'worker_num' => 4,
            'max_coroutine' => 50000,
            'log_level' => SWOOLE_LOG_WARNING,
        ));
        $serv->on('Start', array($this, 'onStart'));
        $serv->on('Request', array($this, 'onRequest'));
        $serv->start();
    }

    function onStart($serv)
    {
        $this->serv = $serv;
        echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
    }

    function onRequest($req, $resp)
    {
        $bc = new Co\Http\Client($this->backend_server['host'], $this->backend_server['port']);
        $retval = $bc->get($req->server['request_uri']);
        if ($retval) {
            $resp->end($bc->body);
        } else {
            $resp->end("failed to connect the backend server, errno=" . $bc->errCode . "\n");
        }
    }
}

$serv = new Co_Http_ProxyServer();
$serv->run();
