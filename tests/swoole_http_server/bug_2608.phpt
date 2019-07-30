--TEST--
swoole_http_server: bug #2608
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->get('/examples/test.jpg');
        $data = $client->body;
        Assert::assert(!empty($data));
        Assert::assert(md5($data) === md5_file(TEST_IMAGE));

        $client = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        $client->get('/../../examples/test.jpg');
        $data = $client->body;
        Assert::same($data, "hello world");

        $pm->kill();
    });
    Swoole\Event::wait();
    unlink(__DIR__.'/examples');
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'enable_static_handler' => true,
        'document_root' => __DIR__,
        'static_file_types' => [],
        'static_file_locations' => ["/examples", ]
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        symlink(dirname(dirname(__DIR__)) . '/examples/', __DIR__.'/examples');
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end("hello world");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
