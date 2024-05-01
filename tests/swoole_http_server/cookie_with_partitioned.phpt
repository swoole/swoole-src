--TEST--
swoole_http_server: cookies with partitioned
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $uri = "http://127.0.0.1:{$pm->getFreePort()}";
        $cookies = httpRequest($uri)['set_cookie_headers'];
		var_dump(strpos($cookies[0], 'partitioned') !== false);
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->cookie('test', '123456789', time() + 3600, '/', 'example.com', true, true, 'None', true, true);
        $response->end('Hello World');
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
bool(true)
DONE
