--TEST--
swoole_http_server: null-only trailer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort());
    fwrite($client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    $response = stream_get_contents($client);
    Assert::endsWith($response, "0\r\n\r\n");
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::true($response->trailer('x-test', null));
        Assert::true($response->write('body'));
        Assert::true($response->end());
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
