--TEST--
swoole_http_server: cookies (max-age)
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

        var_dump(strpos($cookies[0], 'test=123456789') !== false);
        var_dump(strpos($cookies[0], 'expires='.date('D, d-M-Y H:i:s \G\M\T', time() + 3600)) !== false);
        var_dump(strpos($cookies[0], 'Max-Age=3600') !== false);
        var_dump(strpos($cookies[0], 'path=/') !== false);
        var_dump(strpos($cookies[0], 'domain=example.com') !== false);
        var_dump(strpos($cookies[0], 'secure') !== false);
        var_dump(strpos($cookies[0], 'HttpOnly') !== false);
        var_dump(strpos($cookies[0], 'SameSite=None') !== false);
        var_dump(strpos($cookies[1], 'test=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT') !== false);
        var_dump(strpos($cookies[1], 'Max-Age=0') !== false);
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->cookie('test', '123456789', time() + 3600, '/', 'example.com', true, true, 'None');
        $response->cookie('test', '');
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
DONE
