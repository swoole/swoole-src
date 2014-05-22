<?php
class DBServer
{
    protected $pool_size = 20;
    protected $idle_pool = array(); //空闲连接
    protected $busy_pool = array(); //工作连接
    protected $wait_queue = array(); //等待的请求
    protected $wait_queue_max = 100; //等待队列的最大长度，超过后将拒绝新的请求

    /**
     * @var swoole_server
     */
    protected $serv;

    function run()
    {
        $serv = new swoole_server("127.0.0.1", 9509);
        $serv->set(array(
            'worker_num' => 1,
            'max_request' => 0,
        ));

        $serv->on('WorkerStart', array($this, 'onStart'));
        //$serv->on('Connect', array($this, 'onConnect'));
        $serv->on('Receive', array($this, 'onReceive'));
        //$serv->on('Close', array($this, 'onClose'));
        $serv->start();
    }

    function onStart($serv)
    {
        $this->serv = $serv;
        for ($i = 0; $i < $this->pool_size; $i++) {
            $db = new mysqli;
            $db->connect('127.0.0.1', 'root', 'root', 'www4swoole');
            $db_sock = swoole_get_mysqli_sock($db);
            swoole_event_add($db_sock, array($this, 'onSQLReady'));
            $this->idle_pool[] = array(
                'mysqli' => $db,
                'db_sock' => $db_sock,
                'fd' => 0,
            );
        }
        echo "Server: start.Swoole version is [" . SWOOLE_VERSION . "]\n";
    }

    function onSQLReady($db_sock)
    {
        $db_res = $this->busy_pool[$db_sock];
        $mysqli = $db_res['mysqli'];
        $fd = $db_res['fd'];

        echo __METHOD__ . ": client_sock=$fd|db_sock=$db_sock\n";

        if ($result = $mysqli->reap_async_query()) {
            $ret = var_export($result->fetch_all(MYSQLI_ASSOC), true) . "\n";
            $this->serv->send($fd, $ret);
            if (is_object($result)) {
                mysqli_free_result($result);
            }
        } else {
            $this->serv->send($fd, sprintf("MySQLi Error: %s\n", mysqli_error($mysqli)));
        }
        //release mysqli object
        $this->idle_pool[] = $db_res;
        unset($this->busy_pool[$db_sock]);

        //这里可以取出一个等待请求
        if (count($this->wait_queue) > 0) {
            $idle_n = count($this->idle_pool);
            for ($i = 0; $i < $idle_n; $i++) {
                $req = array_shift($this->wait_queue);
                $this->doQuery($req['fd'], $req['sql']);
            }
        }
    }

    function onReceive($serv, $fd, $from_id, $data)
    {
	echo "Received: $data\n";
        //没有空闲的数据库连接
        
	if (count($this->idle_pool) == 0) {
            //等待队列未满
            if (count($this->wait_queue) < $this->wait_queue_max) {
                $this->wait_queue[] = array(
                    'fd' => $fd,
                    'sql' => $data,
                );
            } else {
                $this->serv->send($fd, "request too many, Please try again later.");
            }
        } else {
            $this->doQuery($fd, $data);
        }
    }

    function doQuery($fd, $sql)
    {
        //从空闲池中移除
        $db = array_pop($this->idle_pool);
        /**
         * @var mysqli
         */
        $mysqli = $db['mysqli'];

        for ($i = 0; $i < 2; $i++) {
            $result = $mysqli->query($sql, MYSQLI_ASYNC);
            if ($result === false) {
                if ($mysqli->errno == 2013 or $mysqli->errno == 2006) {
                    $mysqli->close();
                    $r = $mysqli->connect();
                    if ($r === true) continue;
                }
            }
            break;
        }

        $db['fd'] = $fd;
        //加入工作池中
        $this->busy_pool[$db['db_sock']] = $db;
    }
}

$server = new DBServer();
$server->run();
