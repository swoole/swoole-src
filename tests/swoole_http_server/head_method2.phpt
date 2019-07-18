--TEST--
swoole_http_server: HEAD method 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$data = json_encode([
    'code' => 'ok',
    'error' => false,
    'payload' => 'Hello World'
]);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $data) {

    //request 1, HEAD
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1:" . $pm->getFreePort() . '/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'HEAD');
    curl_setopt($ch, CURLOPT_NOBODY, true);

    $result = curl_exec($ch);
    Assert::isEmpty($result);
    $info = curl_getinfo($ch);
    Assert::eq(strlen($data), $info['download_content_length']);

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
        if ($req->server['request_method'] == 'HEAD') {
            $resp->header('Content-Length', strlen($data));
            $resp->end("swoole");
            return;
        }
        $resp->end($data);
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::end(): HEAD method should not return body in /root/codeDir/cppCode/swoole-src/tests/swoole_http_server/head_method2.php on line %d
