--TEST--
swoole_http_server: no compression
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $data = curlGet("http://127.0.0.1:9501/", false);
    assert(md5_file(__DIR__ . '/../../README.md') == md5($data));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP);

    $http->set([
        'http_compression' => false,
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, swoole_http_response $response) {
        $response->end(co::readFile(__DIR__ . '/../../README.md'));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTREGEX--

