--TEST--
swoole_http_server: chunked and pipeline request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

const EOF = "EOF";

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    chunked_request($pm);
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'log_file' => '/dev/null',
        // 'log_level' => SWOOLE_LOG_DEBUG,
        // 'trace_flags' => SWOOLE_TRACE_ALL,
        'http_compression' => false,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->end($request->rawContent() . EOF);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
SUCCESS
