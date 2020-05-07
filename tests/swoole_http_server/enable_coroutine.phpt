--TEST--
swoole_http_server: enable_coroutine setting in server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/") . "\n";
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'enable_coroutine' => false, // close build-in coroutine
        'worker_num' => 1,
        'log_level' => SWOOLE_LOG_NONE,
    ]);
    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->header("Content-Type", "text/plain");
        if ($request->server['request_uri'] == '/co') {
            go(function () use ($response) {
                $response->end(Co::getuid());
            });
        } else {
            $response->end(Co::getuid());
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
-1
1
2
3
