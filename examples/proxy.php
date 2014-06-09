<?php
class ProxyServer
{
    protected $clients;
    protected $backends;
    /**
     * @var swoole_server
     */
    protected $serv;

    function run()
    {
        $serv = new swoole_server("127.0.0.1", 9509);
        $serv->set(array(
            'timeout' => 1, //select and epoll_wait timeout.
            'poll_thread_num' => 1, //reactor thread num
            'worker_num' => 1, //reactor thread num
            'backlog' => 128, //listen backlog
            'max_conn' => 10000,
            'dispatch_mode' => 2,
            //'open_tcp_keepalive' => 1,
            //'log_file' => '/tmp/swoole.log', //swoole error log
        ));
        $serv->on('WorkerStart', array($this, 'onStart'));
        $serv->on('Connect', array($this, 'onConnect'));
        $serv->on('Receive', array($this, 'onReceive'));
        $serv->on('Close', array($this, 'onClose'));
        $serv->on('WorkerStop', array($this, 'onShutdown'));
        //swoole_server_addtimer($serv, 2);
        #swoole_server_addtimer($serv, 10);
        $serv->start();
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
        //backend
        if (isset($this->clients[$fd])) {
            /**
             * @var swoole_client
             */
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
        echo microtime() . ": Client[$fd] backend-sock[{$socket->sock}]: Connect.\n";
       
        $socket->on('connect', function (swoole_client $socket) {
            echo "connect to backend server success\n";
        });
        $socket->on('error', function (swoole_client $socket) {
            echo "connect to backend server fail\n";
            $this->serv->send($this->backends[$socket->sock]['client_fd'], "backend server not connected. please try reconnect.");
            $this->serv->close($this->backends[$socket->sock]['client_fd']);
            $socket->close();
        });

        $socket->on('close', function (swoole_client $socket) {
            echo "backend connection close\n";
        });

        $socket->on('receive', function (swoole_client $socket, $data) {
            //PHP-5.4以下版本可能不支持此写法，匿名函数不能调用$this
            //可以修改为类静态变量
            $this->serv->send($this->backends[$socket->sock]['client_fd'], $data);
        });
        
        if ($socket->connect('127.0.0.1', 80, 0.2))
        {
			$this->backends[$socket->sock] = array(
				'client_fd' => $fd,
				'socket' => $socket,
			);
			$this->clients[$fd] = array(
				'socket' => $socket,
			);
		}
    }

    function onReceive($serv, $fd, $from_id, $data)
    {
        if (!isset($this->clients[$fd])) {
            $this->serv->send($fd, "backend server not connected. please try reconnect.");
            $this->serv->close($fd);
        } else {
            echo microtime() . ": client receive\n";
            $backend_socket = $this->clients[$fd]['socket'];
            $backend_socket->send($data);
            echo microtime() . ": send to backend\n";
            echo str_repeat('-', 100) . "\n";
        }
    }
}

$serv = new ProxyServer();
$serv->run();
