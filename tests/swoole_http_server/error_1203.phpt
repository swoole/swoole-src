--TEST--
swoole_http_server: http_compression
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm)
{
    go(function () use ($pm) {
        try {
            $data =  httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        } catch(Exception $e) {
            Assert::contains($e->getMessage(), 'Connection reset by peer');
        }
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());

    $http->set([
        'http_compression' => false,
        'log_file' => '/dev/null',
        'buffer_output_size' => 128 * 1024,
    ]);

    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });

    $http->on("request", function ($request, swoole_http_response $response) {
        Assert::eq($response->end(str_repeat('A', 256 * 1024)), false);
        Assert::eq(swoole_last_error(), SWOOLE_ERROR_DATA_LENGTH_TOO_LARGE);
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
