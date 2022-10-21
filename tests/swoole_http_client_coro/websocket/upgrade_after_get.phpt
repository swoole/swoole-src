--TEST--
swoole_http_client_coro/websocket: client & server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Coroutine\HTTP\Client;
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {   
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        $client->setHeaders([
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
           
        Assert::assert($client->get('/'));
        echo $client->getBody();
    
        Assert::assert($client->upgrade('/'));

        echo $client->recv(2)->data;
        $client->push("hello");
        echo $client->recv(2)->data;

        $client->close();
    });
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $ws = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $ws->set(array(
        'log_file' => '/dev/null'
    ));
    $ws->on('WorkerStart', function (Swoole\Server $serv) {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });

    $ws->on('open', function ($serv, Swoole\Http\Request $request) {
        $serv->push($request->fd, "msg 1\n");
    });

    $ws->on('message', function ($serv, $frame) {
        co::sleep(0.1);
        $serv->push($frame->fd, "msg 2\n");
    });

    $ws->on('request', function ($req, $resp) {
        $resp->end("OK\n");
    });

    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
msg 1
msg 2
