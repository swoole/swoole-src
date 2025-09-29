--TEST--
swoole_http_client_coro: error handler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->initRandomData(MAX_CONCURRENCY_MID);

$rdata = [];
for ($c = MAX_CONCURRENCY_MID; $c--;) {
    $rdata[] = $pm->getRandomData();
}

$pm->parentFunc = function () use ($pm, $rdata) {
    run(function () use ($pm, $rdata) {
        $cli_map = [];
        $data_map = [];
        for ($c = MAX_CONCURRENCY_MID; $c--;) {
            $cli_map[$c] = $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->setDefer(true);
            $cli->get('/?c=' . $c);
            $data_map[$cli->socket->fd] = $rdata[$c];
        }
        foreach ($cli_map as $cli) {
            Assert::assert($cli->recv());
            Assert::same($cli->body, $data_map[$cli->socket->fd]);
        }

        $pm->kill();
        $pm->wait();

        System::sleep(0.2);

        // when we enable reconnect, we will get connect error
        foreach ($cli_map as $cli) {
            $cli->setDefer(false);
            Assert::assert(!$cli->get('/'));
            Assert::same($cli->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
            Assert::same($cli->errCode, SOCKET_ECONNREFUSED);
        }
    });
    echo "OK\n";
};
$pm->childFunc = function () use ($pm, $rdata) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) use ($pm, $server, $rdata) {
        static $i = 0;
        $i++;
        if ($i <= MAX_CONCURRENCY_MID) {
            $response->end($rdata[$request->get['c']]);
        } else {
            $server->close($request->fd);
        }
    });
    $server->on('shutdown', function (Server $server) use ($pm) {
        foreach ($server->connections as $fd) {
            $server->close($fd);
        }
        $pm->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
