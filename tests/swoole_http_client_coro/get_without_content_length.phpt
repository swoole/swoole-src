--TEST--
swoole_http_client_coro: http GET without Content-Length header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine as co;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    co::create(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set([
            'timeout' => 10
        ]);
        $cli->setHeaders([
            'Connection' => 'close',
            'Accept' => '*/*'
        ]);
        $ret = $cli->get('/');
        Assert::true($ret);
        Assert::same($cli->statusCode, 200);
        Assert::assert(strlen($cli->body) > 1024 * 5);
        $pm->kill();
        echo "OK\n";
    });
    swoole_event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'log_file' => '/dev/null'
    ));
    $serv->on('WorkerStart', function (\swoole_server $serv)
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
        foreach (range(0, 5) as $i) {
            co::sleep(0.1);
            $serv->send($fd, str_repeat('A', rand(1024, 2048)));
        }
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
