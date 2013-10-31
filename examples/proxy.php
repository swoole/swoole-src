<?php
class ProxyServer
{
    static $clients;
    static $backends;

	static function run()
	{
		$serv = swoole_server_create("127.0.0.1", 9509, SWOOLE_BASE, SWOOLE_SOCK_TCP);
		swoole_server_set($serv, array(
			'timeout' => 1,  //select and epoll_wait timeout.
			'poll_thread_num' => 1, //reactor thread num
            'worker_num' => 1, //reactor thread num
			'backlog' => 128,   //listen backlog
			'max_conn' => 10000,
			'dispatch_mode' => 2,
			//'open_tcp_keepalive' => 1,
			//'log_file' => '/tmp/swoole.log', //swoole error log
		));
		swoole_server_handler($serv, 'onWorkerStart', 'ProxyServer::onStart');
		swoole_server_handler($serv, 'onConnect', 'ProxyServer::onConnect');
		swoole_server_handler($serv, 'onReceive', 'ProxyServer::onReceive');
		swoole_server_handler($serv, 'onClose', 'ProxyServer::onClose');
		swoole_server_handler($serv, 'onWorkerStop', 'ProxyServer::onShutdown');
		swoole_server_handler($serv, 'onTimer', 'ProxyServer::onTimer');

		//swoole_server_addtimer($serv, 2);
		#swoole_server_addtimer($serv, 10);
		swoole_server_start($serv);
	}
	static function onStart($serv)
    {
        echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
    }

    static function onShutdown($serv)
    {
        echo "Server: onShutdown\n";
    }

    static function onTimer($serv, $interval)
    {
        //echo "Server：Timer Call.Interval=$interval \n";
    }

    static function onClose($serv, $fd, $from_id)
    {
        //backend
        if(isset(self::$backends[$fd]))
        {
            $backend_client = self::$backends[$fd]['client'];
        }
        else
        {
            $backend_client = self::$clients[$fd]['client'];
            swoole_reactor_del($serv, $backend_client->sock, self::$backends[$backend_client->sock]['reactor_id']);
            $backend_client->close();
        }
        unset(self::$backends[$backend_client->sock], self::$clients[$fd]);
    }

    static function onConnect($serv, $fd, $from_id)
    {
        echo microtime().": Client: Connect.\n";
        $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_ASYNC);
        self::$backends[$client->sock] = array(
            'conn' => $fd,
            'client' => $client,
            'reactor_id' => $from_id,
        );
        self::$clients[$fd] = array(
            'client' => $client,
        );
        $client->on('connect', function($client){
            echo "connect to backend server\n";
        });
        $client->on('receive', function($cli){

        });

        if($client->connect('127.0.0.1', 9501, 0.2))
        {
            if(swoole_reactor_add($serv, $client->sock))
            {

                echo "success\n";
                return;
            }
        }
        echo "fail.\n";
    }

    static function onReceive($serv, $fd, $from_id, $data)
    {
        //backend
        if(isset(self::$backends[$fd]))
        {
            echo microtime().": backend receive\n";
            $client_sock = self::$backends[$fd]['conn'];
            swoole_server_send($serv, $client_sock, $data);
            echo microtime().": send to client\n";
        }
        //client
        else
        {
            echo microtime().": client receive\n";
            $backend_client = self::$clients[$fd]['client'];
            $backend_client->send($data);
            echo microtime().": send to backend\n";
            echo str_repeat('-', 100)."\n";
        }
    }
}

ProxyServer::run();