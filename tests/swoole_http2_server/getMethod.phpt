--TEST--
swoole_http2_server: getMethod
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($cli->connect());
        $req = new Swoole\Http2\Request();
        $req->method = 'POST';
        $req->path = '/api';
        $req->headers = [
            'user-agent' => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
            'accept-encoding' => 'gzip'
        ];
        $req->data = '{"type":"up"}';
        $cli->send($req);
        $response = $cli->recv();
        $json = json_decode($response->data);
        Assert::same($json->request_method, 'POST');
        Assert::same($json->getMethod, 'POST');
        $pm->kill();
    });
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('::', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP6);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        $request_method = $request->server['request_method'];
        $getMethod = $request->getMethod();
        $response->end(json_encode(compact('request_method', 'getMethod'), JSON_PRETTY_PRINT) . "\n");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
