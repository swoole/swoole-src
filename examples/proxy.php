<?php
class ProxyServer
{
    protected $clients;
    protected $backends;
    protected $serv;

	function run()
	{
		$serv = swoole_server_create("127.0.0.1", 9509);
		swoole_server_set($serv, array(
			'timeout' => 1,  //select and epoll_wait timeout.
			'poll_thread_num' => 1, //reactor thread num
            'worker_num' => 1, //reactor thread num
			'backlog' => 128,   //listen backlog
			'max_conn' => 10000,
			'dispatch_mode' => 2,
			//'open_tcp_keepalive' => 1,
			'log_file' => '/tmp/swoole.log', //swoole error log
		));
		swoole_server_handler($serv, 'onWorkerStart', array($this, 'onStart'));
		swoole_server_handler($serv, 'onConnect',  array($this, 'onConnect'));
		swoole_server_handler($serv, 'onReceive',  array($this, 'onReceive'));
		swoole_server_handler($serv, 'onClose',   array($this, 'onClose'));
		swoole_server_handler($serv, 'onWorkerStop',  array($this, 'onShutdown'));
		//swoole_server_addtimer($serv, 2);
		#swoole_server_addtimer($serv, 10);
		swoole_server_start($serv);
	}
	function onStart($serv)
    {
        $this->serv = $serv;
        echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
    }

    function onShutdown($serv)
    {
        echo "Server: onShutdown\n";
    }

    function onClose($serv, $fd, $from_id)
    {
        //backend
        if(isset($this->clients[$fd]))
        {
            $backend_client = $this->clients[$fd]['socket'];
            unset($this->clients[$fd]);
            $backend_client->close();
            unset($this->backends[$backend_client->sock]);
            echo "client close\n";
        }
    }

    function onConnect($serv, $fd, $from_id)
    {
        $socket = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        echo microtime().": Client[$fd] backend-sock[{$socket->sock}]: Connect.\n";
        $this->backends[$socket->sock] = array(
            'client_fd' => $fd,
            'socket' => $socket,
        );
        $this->clients[$fd] = array(
            'socket' => $socket,
        );
        $socket->on('connect', function($socket){
            echo "connect to backend server success\n";
        });
        $socket->on('error', function($socket){
            echo "connect to backend server fail\n";
        });
        $socket->on('receive', function($socket){
            swoole_server_send($this->serv, $this->backends[$socket->sock]['client_fd'], $socket->recv());
        });
        $socket->connect('127.0.0.1', 9501, 0.2);
    }

    function onReceive($serv, $fd, $from_id, $data)
    {
        echo microtime().": client receive\n";
        $backend_socket = $this->clients[$fd]['socket'];
        $backend_socket->send($data);
        echo microtime().": send to backend\n";
        echo str_repeat('-', 100)."\n";
    }
}

$serv = new ProxyServer();
$serv->run();