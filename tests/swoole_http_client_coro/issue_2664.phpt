--TEST--
swoole_http_client_coro: set_cookie_headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\Run(function () use ($pm) {
        var_dump(httpRequest("http://127.0.0.1:{$pm->getFreePort()}")['set_cookie_headers']);
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $time_left = time() + 84600;
        $response->cookie('key1', 'val1', $time_left, '/', 'id.test.com');
        $response->cookie('key1', '', 0, '/', 'test.com');
        $response->cookie('key2', 'val2', $time_left, '/', 'id.test.com');
        $response->cookie('key2', '', 0, '/', 'test.com');
        $response->end("<h1>Hello Swoole. #" . rand(1000, 9999) . "</h1>");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(4) {
  [0]=>
  string(76) "key1=val1; expires=%s; path=/; domain=id.test.com"
  [1]=>
  string(76) "key1=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; domain=test.com"
  [2]=>
  string(76) "key2=val2; %s; path=/; domain=id.test.com"
  [3]=>
  string(76) "key2=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; path=/; domain=test.com"
}
