--TEST--
swoole_http_server: http redirect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $data = curlGet("http://127.0.0.1:{$pm->getFreePort()}/");
    assert(!empty($data));
    assert(md5($data) === md5_file(TEST_IMAGE));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/',
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, swoole_http_response $response) {
        if ($request->server['path_info'] == '/') {
            $response->redirect('/test.jpg');
        }
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
