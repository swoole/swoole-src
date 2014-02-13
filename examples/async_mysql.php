<?php
if(!function_exists('swoole_get_mysqli_sock')) {
	die("no async_mysql support\n");
}
class DBServer
{
    static $clients;
    static $backends;

    /**
     * @var mysqli
     */
    static protected $db;
    static protected $locks = array();
    static $serv;
    static $last_fd;

    static function run()
    {
        $serv = new swoole_server("127.0.0.1", 9509);
        $serv->setopt(array(
            'timeout' => 1,  //select and epoll_wait timeout.
            'worker_num' => 1,
            'poll_thread_num' => 1, //reactor thread num
            'backlog' => 128,   //listen backlog
            'max_conn' => 10000,
            'dispatch_mode' => 2,
            //'open_tcp_keepalive' => 1,
            //'log_file' => '/tmp/swoole.log', //swoole error log
        ));
        $serv->on('WorkerStart', 'DBServer::onStart');
        $serv->on('Connect', 'DBServer::onConnect');
        $serv->on('Receive', 'DBServer::onReceive');
        $serv->on('Close', 'DBServer::onClose');
        $serv->on('WorkerStop', 'DBServer::onShutdown');
        $serv->on('Timer', 'DBServer::onTimer');

        //swoole_server_addtimer($serv, 2);
        #swoole_server_addtimer($serv, 10);
        $serv->start();
        self::$serv = $serv;
    }

    static function onStart($serv)
    {
        self::$db = new mysqli;
        self::$db->connect('127.0.0.1', 'root', 'root', 'test');
        echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
        $db_sock = swoole_get_mysqli_sock(self::$db);
        swoole_event_add($db_sock, 'DBServer::onSQLReady');
        self::$serv = $serv;
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

    }

    static function onConnect($serv, $fd, $from_id)
    {

    }

    static function onSQLReady($db_sock)
    {
        $fd = self::$last_fd;
        echo __METHOD__.": client_sock=$fd|db_sock=$db_sock\n";
        if ($result = self::$db->reap_async_query())
        {
            $ret = var_export($result->fetch_all(MYSQLI_ASSOC), true)."\n";
            self::$serv->send($fd, $fd, $ret);
            if (is_object($result))
            {
                mysqli_free_result($result);
            }
        }
        else
        {
            self::$serv->send($fd, sprintf("MySQLi Error: %s\n", mysqli_error(self::$db)));
        }
    }

    static function onReceive($serv, $fd, $from_id, $data)
    {
        self::$db->query($data, MYSQLI_ASYNC);
        self::$last_fd = $fd;
    }
}

DBServer::run();
