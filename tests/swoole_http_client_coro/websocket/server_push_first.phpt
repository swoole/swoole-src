--TEST--
swoole_http_client_coro/websocket: websocket server push first
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use SwooleTest\WaitRef;

$pm = new SwooleTest\ProcessManager;
$pm->initFreePorts();
$pm->initRandomDataArray(2, 0, true);

Co\run(function () use ($pm) {
    $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);
    go(function () use ($pm, $server) {
        $server->handle(
            '/websocket',
            function ($request, $ws) use ($pm) {
                $ws->upgrade();
                $ws->push($pm->getRandomDataElement(0));
                $ws->push($pm->getRandomDataElement(1));
            }
        );
        $server->handle(
            '/shutdown',
            function ($request, $response) use ($server) {
                echo "shutdown\n";
                $response->status(200);
                $server->shutdown();
            }
        );
        $server->start();
    });

    go(function () use ($pm, $server) {
        $wr = WaitRef::create();
        for ($c = MAX_CONCURRENCY_LOW; $c--;) {
            go(function () use ($pm, $wr) {
                $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
                $cli->set(['timeout' => 5]);
                $ret = $cli->upgrade('/websocket');
                Assert::assert($ret);
                $ret = $cli->recv();
                Assert::same($ret->data, $pm->getRandomDataElement(0));
                $ret = $cli->recv();
                Assert::same($ret->data, $pm->getRandomDataElement(1));
            });
        }
        WaitRef::wait($wr);
        $server->shutdown();
    });
});

?>
--EXPECT--
