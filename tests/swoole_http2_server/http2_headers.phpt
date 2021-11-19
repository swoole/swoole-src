--TEST--
swoole_http2_server: array headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $output = `curl --http2-prior-knowledge --silent -I http://127.0.0.1:{$pm->getFreePort()}`;
    Assert::contains($output, 'HTTP/2 200');
    Assert::contains($output, 'test-value: a');
    Assert::contains($output, 'test-value: d5678');
    Assert::contains($output, 'test-value: e');
    Assert::contains($output, 'test-value: 5678');
    Assert::contains($output, 'test-value: 3.1415926');
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->header('test-value', [
            "a\r\n",
            'd5678',
            "e  \n ",
            null,
            5678,
            3.1415926,
        ]);
        $response->end("<h1>Hello Swoole.</h1>");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
