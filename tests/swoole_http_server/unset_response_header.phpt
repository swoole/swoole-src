--TEST--
swoole_http_server: unset header of response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $data = curlGet('http://127.0.0.1:9501/');
    assert(!empty($data));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->header("Some-Header", "some value");           // done
        $response->status(500);
        unset($response->header);
        $response->header("Content-Type", "text/plain; charset=utf-8");
        $response->end("just an 500 error for fun\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
