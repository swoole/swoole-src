<?php
class DBServer
{
    static $clients;
    static $backends;

    /**
     * @var mysqli
     */
    static protected $db;
    static $serv;

    static function run()
    {
        $serv = swoole_server_create("127.0.0.1", 9509, SWOOLE_BASE, SWOOLE_SOCK_TCP);
        swoole_server_set($serv, array(
            'timeout' => 1,  //select and epoll_wait timeout.
            'poll_thread_num' => 1, //reactor thread num
            'backlog' => 128,   //listen backlog
            'max_conn' => 10000,
            'dispatch_mode' => 2,
            //'open_tcp_keepalive' => 1,
            //'log_file' => '/tmp/swoole.log', //swoole error log
        ));
        swoole_server_handler($serv, 'onStart', 'DBServer::onStart');
        swoole_server_handler($serv, 'onConnect', 'DBServer::onConnect');
        swoole_server_handler($serv, 'onReceive', 'DBServer::onReceive');
        swoole_server_handler($serv, 'onClose', 'DBServer::onClose');
        swoole_server_handler($serv, 'onShutdown', 'DBServer::onShutdown');
        swoole_server_handler($serv, 'onTimer', 'DBServer::onTimer');

        //swoole_server_addtimer($serv, 2);
        #swoole_server_addtimer($serv, 10);
        swoole_server_start($serv);
        self::$serv = $serv;
    }

    static function onStart($serv)
    {
        self::$db = new mysqli;
        self::$db->connect('127.0.0.1', 'root', 'root', 'test');
        echo "Server: start.Swoole version is [".SWOOLE_VERSION."]\n";
        $db_sock = swoole_mysqli_get_sock(self::$db);
        swoole_reactor_add_callback($serv, $db_sock, 'DBServer::onSQLReady');
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

    function onSQLReady($sock, $from_id)
    {
        echo __METHOD__.": sock=$sock|from_id=$from_id\n";
        if ($result = self::$db->reap_async_query())
        {
            print_r($result->fetch_row());
            if (is_object($result))
            {
                mysqli_free_result($result);
            }
        }
        else
        {
            echo sprintf("MySQLi Error: %s", mysqli_error(self::$db));
        }
    }

    static function onReceive($serv, $fd, $from_id, $data)
    {
        self::$db->query("show tables", MYSQLI_ASYNC);
    }
}

DBServer::run();