--TEST--
swoole_http_server: allow setting content length header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$data = str_repeat('a', 100);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $data) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:" . $pm->getFreePort() . '/');
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    Assert::assert(strrpos($header, 'Content-Length: 50') > 0);
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $data) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on('request', function ($req, Swoole\Http\Response $resp) use ($data) {
        $resp->header('Content-Type', 'application/json');
        $resp->header('Content-Length', 50);
        $resp->end($data);
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
