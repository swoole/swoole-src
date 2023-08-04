--TEST--
swoole_http_server: bug #5114
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/http/UPPER.TXT");
        Assert::same($response['statusCode'], 200);
        Assert::same($response['headers']['content-type'], 'text/plain');
        Assert::same($response['body'], "HELLO WORLD!\n");

        $response = httpRequest("http://127.0.0.1:{$pm->getFreePort()}/http/test.txt");
        Assert::same($response['statusCode'], 200);
        Assert::same($response['headers']['content-type'], 'text/plain');
        Assert::same($response['body'], "hello world!\n");
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'enable_static_handler' => true,
        'document_root' => dirname(dirname(__DIR__)) . '/examples/',
        'static_handler_locations' => ['/static', '/']
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        $response->end('hello world');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
