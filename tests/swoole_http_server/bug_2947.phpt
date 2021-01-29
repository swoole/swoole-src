--TEST--
swoole_http_server: Bug Github#2947
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $headers = httpGetHeaders(
            "http://127.0.0.1:{$pm->getFreePort()}",
            [
                'headers' => ['Accept-Encoding' => 'gzip, br'],
                'data' => $pm->getRandomData()
            ]
        );
        $encoding = $headers['content-encoding'] ?? '';
        if (defined('SWOOLE_HAVE_BROTLI')) {
            Assert::same($encoding, 'br');
        } elseif (defined('SWOOLE_HAVE_ZLIB')) {
            Assert::same($encoding, 'gzip');
        }
        if (defined('SWOOLE_HAVE_COMPRESSION')) {
            phpt_var_dump($encoding);
        }
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
        Assert::same($request->server['request_method'], 'POST');
        Assert::same($request->rawContent(), $pm->getRandomData());
        $response->end(str_repeat('OK', 16));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
