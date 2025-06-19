--TEST--
swoole_http_client_coro/websocket: client & server
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
skip_if_darwin_todo();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Co\http\Client;
use Swoole\Event;
use Swoole\Http\Request;
use Swoole\WebSocket\Server;

$pm = new ProcessManager();

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => -1]);
        $cli->setHeaders([]);
        $ret = $cli->upgrade('/');

        if (!$ret) {
            echo "ERROR\n";
            return;
        }
        echo $cli->recv()->data;
        for ($i = 0; $i < 5; $i++) {
            $cli->push('hello server');
            echo $cli->recv()->data;
            co::sleep(0.1);
        }
    });
    Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $ws = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $ws->set([
        'log_file' => '/dev/null',
    ]);
    $ws->on('WorkerStart', function (Server $serv) {
        /*
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });

    $ws->on('open', function (Server $serv, Request $request) {
        $ip = Co::gethostbyname(TEST_DOMAIN_1);
        if ($ip) {
            $serv->push($request->fd, "start\n");
        } else {
            $serv->push($request->fd, 'error: ' . swoole_last_error() . "\n");
        }
    });

    $ws->on('message', function ($serv, $frame) {
        co::sleep(0.1);
        $serv->push($frame->fd, "hello client\n");
    });

    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
start
hello client
hello client
hello client
hello client
hello client
