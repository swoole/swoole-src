--TEST--
swoole_http_server: disable coroutine and use go
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        for ($n = 0; $n > MAX_REQUESTS; $n++) {
            Assert::assert(httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") == $n);
        }
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'enable_coroutine' => false, // close build-in coroutine
    ]);
    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        go(function () use ($response) {
            co::sleep(0.001);
            $cid = go(function () use ($response) {
                co::yield();
                $response->end(Co::getuid());
            });
            co::resume($cid);
        });
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
