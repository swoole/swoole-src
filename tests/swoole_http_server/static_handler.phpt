--TEST--
swoole_http_server: cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $data = curlGet('http://127.0.0.1:9501/test.jpg');
    assert(!empty($data));
    assert(md5($data) === md5_file(TEST_IMAGE));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/',
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(TEST_IMAGE);
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
