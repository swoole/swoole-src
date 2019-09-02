--TEST--
swoole_http_server: Bug Github#2786
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:" . $pm->getFreePort() . '/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "[]");
    curl_setopt($ch, CURLOPT_POST, 1);
    $headers = [];
    $headers[] = 'Transfer-Encoding: chunked';
    $headers[] = 'Content-Type: application/json;charset=UTF-8';
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $result = curl_exec($ch);
    curl_close($ch);
    echo $result . PHP_EOL;
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::same($request->server['request_method'], 'POST');
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
