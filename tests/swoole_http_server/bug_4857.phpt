--TEST--
swoole_http_server: bug Github#4857  Invalid "Transfer-Encoding: chunked" header appended
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {

        // without special content-length
        $headers = httpGetHeaders(
            "http://127.0.0.1:{$pm->getFreePort()}?encoding=1",
            [
                'headers' => ['Accept-Encoding' => 'gzip, br'],
            ]
        );
        var_dump($headers);

        // without content-length
        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}");
        var_dump($headers);

        // with content-length
        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}?normal=1");
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
        $data = '宛如繁星般，宛如皎月般';
        if (isset($request->get['normal'])) {
            $response->header('Content-Length', mb_strlen($data));
            $response->end($data);
        } elseif (isset($request->get['encoding'])) {
            $response->header('Content-Length', 1000);
            $response->end($data);
        } else {
            $response->header('Content-Length', 100);
            $response->write($data);
            $response->end();
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::end(): The client has set 'Accept-Encoding', 'Content-Length' is ignored in %s on line %d
array(6) {
  ["server"]=>
  string(18) "swoole-http-server"
  ["connection"]=>
  string(10) "keep-alive"
  ["content-type"]=>
  string(9) "text/html"
  ["date"]=>
  string(%d) %s
  ["content-length"]=>
  string(%d) %s
  ["content-encoding"]=>
  string(%d) %s
}

Warning: Swoole\Http\Response::write(): You have set 'Transfer-Encoding', 'Content-Length' is ignored in %s on line %d
array(5) {
  ["server"]=>
  string(18) "swoole-http-server"
  ["connection"]=>
  string(10) "keep-alive"
  ["content-type"]=>
  string(9) "text/html"
  ["date"]=>
  string(%d) %s
  ["transfer-encoding"]=>
  string(7) "chunked"
}

Warning: Swoole\Http\Response::end(): The client has set 'Accept-Encoding', 'Content-Length' is ignored in %s on line %d
array(6) {
  ["server"]=>
  string(18) "swoole-http-server"
  ["connection"]=>
  string(10) "keep-alive"
  ["content-type"]=>
  string(9) "text/html"
  ["date"]=>
  string(%d) %s
  ["content-length"]=>
  string(%d) %s
  ["content-encoding"]=>
  string(%d) %s
}
DONE