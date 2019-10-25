--TEST--
swoole_http_server: PURGE method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$html = '<h1>Purged</h1>';

$pm->parentFunc = function ($pid) use ($pm, $html) {
    go(function () use ($pm, $html) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/", ['method' => 'PURGE']);
        Assert::same($data, $html);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $html) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function ($request, $response) use ($html) {
        if ($request->server['request_method'] == 'PURGE') {
            $response->end($html);
            return;
        }
        $response->end();
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
