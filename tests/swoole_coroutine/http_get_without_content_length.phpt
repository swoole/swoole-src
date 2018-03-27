--TEST--
swoole_coroutine: http GET without Content-Length header
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/lib/curl.php";

use Swoole\Coroutine as co;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    co::create(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', 9501);
        $cli->set([
            'timeout' => 10
        ]);
        $cli->setHeaders([
            'Connection' => 'close',
            'Accept' => '*/*'
        ]);
        $ret = $cli->get('/');
        assert($ret == true);
        assert($cli->statusCode == 200);
        $pm->kill();
        echo "OK\n";
    });
    swoole_event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $serv->set(array(
        'log_file' => '/dev/null'
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $threadId, $data)
    {
        $serv->send($fd, "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
