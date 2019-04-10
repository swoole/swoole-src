<?php

class Co_TCP_ProxyServer
{
    protected $backend_server = ['host' => '127.0.0.1', 'port' => 80];
    protected $serv;

    function run()
    {
        Co::set(['enable_reuse_port' => true]);
        $serv = new Swoole\Server("127.0.0.1", 9509);
        $serv->set(array(
            'worker_num' => 4,
            'max_coroutine' => 50000,
            'log_level' => SWOOLE_LOG_WARNING,
        ));
        $serv->on('Start', array($this, 'onStart'));
        $serv->on('Receive', array($this, 'onReceive'));
        $serv->start();
    }

    function onStart($serv)
    {
        $this->serv = $serv;
        echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
    }

    function onReceive($serv, $fd, $tid, $data)
    {
        $socket = new Co\Client(SWOOLE_SOCK_TCP);
        if ($socket->connect($this->backend_server['host'], $this->backend_server['port'], 2.0)) {
            $socket->send($data);
            $html = '';
            while (true) {
                $output = $socket->recv(8192 * 512);
                if (!$output) {
                    break;
                }
                $html .= $output;
                if (strlen($html) >= 10918) {
                    break;
                }
            }
            $serv->send($fd, $html);
            if (strstr($data, 'Connection: Keep-Alive') === false) {
                $serv->close($fd);
            }
        } else {
            echo "failed to connect the backend server, errno=" . $socket->errCode . "\n";
        }
    }
}

$serv = new Co_TCP_ProxyServer();
$serv->run();
