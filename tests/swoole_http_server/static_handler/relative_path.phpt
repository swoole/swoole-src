--TEST--
swoole_http_server: static handler with relative path
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/examples/test.jpg");
        assert(!empty($data));
        assert(md5($data) === md5_file(TEST_IMAGE));

        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test.jpg");
        assert($data == TEST_IMAGE);
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
       'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => __DIR__ . '/../../../'
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
DONE
