--TEST--
swoole_http_server_coro: websocket greeter and reply twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    for ($c = MAX_CONCURRENCY; $c--;) {
        go(function () use ($pm, &$count) {
            global $count;
            $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            $cli->set(['timeout' => 5]);
            $ret = $cli->upgrade('/websocket');
            Assert::assert($ret);
            $data = sha1(get_safe_random(mt_rand(0, 1024)));
            for ($n = MAX_REQUESTS; $n--;) {
                $cli->push($data);
                $ret = $cli->recv();
                Assert::same($ret->data, "Hello {$data}!");
                $ret = $cli->recv();
                Assert::same($ret->data, "How are you, {$data}?");
                $count++;
            }
        });
    }
    swoole_event_wait();
    Assert::same($count, (MAX_CONCURRENCY * MAX_REQUESTS));
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/websocket', function ($request, $ws) {
            $ws->upgrade();
            while (true) {
                $frame = $ws->recv();
                if ($frame === false) {
                    echo "error : " . swoole_last_error() . "\n";
                    break;
                } else if ($frame == '') {
                    break;
                } else {
                    Assert::greaterThan($frame->fd, 0);
                    $ws->push("Hello {$frame->data}!");
                    $ws->push("How are you, {$frame->data}?");
                }
            }
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
