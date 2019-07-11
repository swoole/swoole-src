--TEST--
swoole_client_coro: tcp client with eof [02]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

class MyPool
{
    protected $pool;

    public function __construct()
    {
        $this->pool = new SplQueue();
    }

    public function put($mysql)
    {
        $this->pool->enqueue($mysql);
    }

    public function get()
    {
        //有空闲连接
        if (count($this->pool) > 0) {
            return $this->pool->dequeue();
        }

        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_KEEP);
        $client->set(array(
            'open_eof_split' => true, //打开EOF_SPLIT检测
            'package_eof' => "\r\n",
        ));
        $res = $client->connect('127.0.0.1', 8000, 3);
        if ($res == false) {
            echo "create connect failed, errCode=".$client->errCode."\n";
            return false;
        } else {
            return $client;
        }
    }
}

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () {
        $pool = new MyPool();
        for ($j = 0; $j < 2; $j++)
        {
            $con = [];
            for ($i = 0; $i < 4; $i++)
            {
                $client = $pool->get();
                $client->send('hello' . $i . "\r\n");
                $con[] = $client;
            }
            co::sleep(0.1);
            foreach ($con as $key => $value)
            {
                echo "recv:" . trim($value->recv()) . "\n";
                $pool->put($value);
            }
        }
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('0.0.0.0', 8000, SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $serv->set(array(
        'open_eof_split' => true,
        'package_eof' => "\r\n",
    ));
    $serv->on('receive', function ($serv, $fd, $rid, $data) {
        $ret = "server reply {" . trim($data) . "} \r\n";
        $serv->send($fd, $ret);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
recv:server reply {hello0}
recv:server reply {hello1}
recv:server reply {hello2}
recv:server reply {hello3}
recv:server reply {hello0}
recv:server reply {hello1}
recv:server reply {hello2}
recv:server reply {hello3}
