--TEST--
swoole_client_sync: connect 1 - 3 nonblocking connect & select
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $r = $cli->connect('127.0.0.1', $pm->getFreePort(), 1);
    Assert::assert($r);
    $r = $w = $e = [$cli];
    $n = swoole_client_select($r, $w, $e, 0);
    Assert::same($n, 1);
    Assert::same(count($w), 1);
    Assert::same(count($e), 0);
    Assert::same(count($r), 0);
    $cli->close();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
