--TEST--
swoole_http_server: GitHub issue #5186
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $content = "POST / HTTP/1.1\r\nHost: 127.0.0.1:{$pm->getFreePort()}\r\nConnection: keep-alive\r\nContent-Length: 44\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundaryOldDnwBESVoBBtI5\r\nAccept-Encoding: gzip, deflate\r\n\r\n------WebKitFormBoundaryOldDnwBESVoBBtI5--\r\n\r\n";
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->connect('127.0.0.1', $pm->getFreePort(), 0.5);
        $client->send($content);
        $client->close();
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) use ($http) {
        var_dump($request->files);
        $response->end('Hello World');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
NULL
