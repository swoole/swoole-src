--TEST--
swoole_http_client_coro: slow server
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

        Assert::same($cli->headers['server'], 'nginx');
        Assert::same($cli->headers['x-server'], 'swoole');
        Assert::same($cli->headers['content-type'], 'text/html');
        Assert::eq($cli->headers['content-length'], strlen($cli->body) );

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
        $html = base64_encode(random_bytes(rand(1024, 65536)));
        $len = strlen($html);
        $data = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\nContent-Length: $len\r\nX-Server: swoole\r\n\r\n$html";
        $chunks = str_split($data, 5);
        foreach ($chunks as $out) {
            $serv->send($fd, $out);
            usleep(100);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
