--TEST--
swoole_http2_server: sendfile [content-type]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort(), false);
        $cli->set(['timeout' => -1]);
        Assert::true($cli->connect());
        Assert::assert($cli->send(new Swoole\Http2\Request));
        $response = $cli->recv();
        Assert::notEmpty($response);
        Assert::same(md5_file(TEST_IMAGE), md5($response->data));
        Assert::same($response->statusCode, 200);
        Assert::same($response->headers['content-type'], 'image/jpeg');
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        if (!Assert::true($response->sendfile(TEST_IMAGE))) {
            echo swoole_strerror(swoole_last_error()) . PHP_EOL;
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
