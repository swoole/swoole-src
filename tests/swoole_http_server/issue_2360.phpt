--TEST--
swoole_http_server: issue 2360 (swoole_http_server silently fails to read requests)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager();
$pm->setRandomFunc(function () {
    $size = mt_rand(1024, 65536);
    $data = '';
    for ($i = 0; $i < $size; $i++) {
        $data .= sprintf('%01x', $i % 16);
    }
    return $data;
});
$pm->initRandomDataEx(1, MAX_REQUESTS);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['socket_buffer_size' => 1024]);
        for ($n = MAX_REQUESTS; $n--;) {
            $data = $pm->getRandomData();
            assert($cli->post('/', $data) === true);
            assert($cli->statusCode === 200);
            assert($cli->body === $data);
            phpt_echo("posting " . strlen($data) . " bytes\n");
        }
        $cli->close();
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'log_file' => '/dev/null',
        'socket_buffer_size' => 1024
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        phpt_echo("received {$request->header['content-length']} bytes\n");
        if (assert($request->rawContent() === $pm->getRandomData())) {
            $response->end($request->rawContent());
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
