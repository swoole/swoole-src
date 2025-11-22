--TEST--
swoole_http_server: max execution time
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(2);
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $result = httpGetBody("http://127.0.0.1:{$pm->getFreePort()}");
        var_dump($result);
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set(
        [
            'enable_coroutine' => true,
            'hook_flags' => SWOOLE_HOOK_ALL,
        ]
    );

    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        try {
            Swoole\Coroutine::setTimeLimit(1);
            sleep(5);
            $response->header('Content-Type', 'text/plain');
            $response->end('Hello World');
        } catch (\Throwable $e) {
            Assert::true($e instanceof \Swoole\Coroutine\TimeoutException);
            $response->end('execution timeout');
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
string(17) "execution timeout"
