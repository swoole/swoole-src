--TEST--
swoole_coroutine: co::create before server create [1]
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_unsupported();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('SECRET', SwooleTest\RandStr::getBytes(rand(1024, 8192)));

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $data = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        Assert::notEmpty($data);
        Assert::same($data, SECRET);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        Co::sleep(0.1);
        $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
        $http->set([
            'log_file' => '/dev/null',
            "worker_num" => 1,
        ]);
        $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
            $pm->wakeup();
        });
        $http->on("request", function ($request, Swoole\Http\Response $response) {
            $response->end(SECRET);
        });

        $http->start();
    });
    Swoole\Event::wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
