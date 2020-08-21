--TEST--
swoole_http_server_coro: close websocket connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    go(function () use ($pm) {
        global $count;
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        $ret = $cli->upgrade('/websocket');
        Assert::assert($ret);
        $data = sha1(get_safe_random(mt_rand(0, 1024)));
        $cli->push($data);
        $ret = $cli->recv();
        Assert::same($ret->data, "Hello {$data}!");
        $s = microtime(true);
        $ret = $cli->recv();
        Assert::lessThan(microtime(true) - $s, 0.002);
        Assert::same($ret, false);
    });
    swoole_event_wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/websocket', function ($request, $ws) {
            $ws->upgrade();
            $frame = $ws->recv();
            if ($frame === false) {
                echo "error : " . swoole_last_error() . "\n";
            } else if ($frame === '' or $frame->data === '') {
                echo "close\n";
            } else {
                Assert::greaterThan($frame->fd, 0);
                $ws->push("Hello {$frame->data}!");
                $ws->close();
            }
            System::sleep(0.5);
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            echo "shutdown\n";
            $response->status(200);
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    swoole_event_wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
