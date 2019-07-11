--TEST--
swoole_http_server/static_handler: static handler with relative path
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/examples/test.jpg");
        Assert::assert(!empty($data));
        Assert::assert(md5($data) === md5_file(TEST_IMAGE));

        /**
         * 命中location，但文件不存在，直接返回 404
         */
        $status = httpGetStatusCode("http://127.0.0.1:{$pm->getFreePort()}/examples/test2.jpg");
        Assert::assert($status == 404);

        /**
         * 动态请求
         */
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test.jpg");
        Assert::assert($data == TEST_IMAGE);

        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
//        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => __DIR__ . '/../../../',
        'static_handler_locations' => ["/examples", ]
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
