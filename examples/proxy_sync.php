<?php
class ProxyServer
{
    protected $clients;
    protected $backends;
    protected $serv;

    function run()
    {
        $serv = swoole_server_create("127.0.0.1", 9509, SWOOLE_PROCESS);
        swoole_server_set($serv, array(
            'timeout' => 1, //select and epoll_wait timeout.
            'poll_thread_num' => 1, //reactor thread num
            'worker_num' => 32, //reactor thread num
            'backlog' => 128, //listen backlog
            'max_conn' => 10000,
            'dispatch_mode' => 2,
            //'open_tcp_keepalive' => 1,
            //'log_file' => '/tmp/swoole.log', //swoole error log
        ));
        swoole_server_handler($serv, 'onWorkerStart', array($this, 'onStart'));
        swoole_server_handler($serv, 'onConnect', array($this, 'onConnect'));
        swoole_server_handler($serv, 'onReceive', array($this, 'onReceive'));
        swoole_server_handler($serv, 'onClose', array($this, 'onClose'));
        swoole_server_handler($serv, 'onWorkerStop', array($this, 'onShutdown'));
        //swoole_server_addtimer($serv, 2);
        #swoole_server_addtimer($serv, 10);
        swoole_server_start($serv);
    }

    function onStart($serv)
    {
        $this->serv = $serv;
        echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
    }

    function onShutdown($serv)
    {
        echo "Server: onShutdown\n";
    }

    function onClose($serv, $fd, $from_id)
    {

    }

    function onConnect($serv, $fd, $from_id)
    {
        
    }

    function onReceive($serv, $fd, $from_id, $data)
    {
		$socket = new swoole_client(SWOOLE_SOCK_TCP);
        if($socket->connect('127.0.0.1', 80, 0.5))
        {
			$socket->send($data);
			$serv->send($fd, $socket->recv());
		}
        unset($socket);
        $serv->close($fd);
    }
}

$serv = new ProxyServer();
$serv->run();
