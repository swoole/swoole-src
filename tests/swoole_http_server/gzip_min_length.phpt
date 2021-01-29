--TEST--
swoole_http_server: gzip_min_length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm)
{
    run(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::assert(md5_file(__DIR__ . '/../../README.md') == md5($data));

    });
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm)
{
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->set(['gzip_min_length' => 128,]);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function ($request, swoole_http_response $response) {

        //
        $response->end(str_repeat('A', 128));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
