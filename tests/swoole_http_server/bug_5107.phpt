--TEST--
swoole_http_server: bug Github#5107  Error response status
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}");
        var_dump($headers);
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
         $response->status(200, "status");
         $response->end("Hello World");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
array(5) {
  ["server"]=>
  string(18) "swoole-http-server"
  ["date"]=>
  string(%d) %s
  ["connection"]=>
  string(10) "keep-alive"
  ["content-type"]=>
  string(9) "text/html"
  ["content-length"]=>
  string(2) "11"
}
DONE
