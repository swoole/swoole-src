--TEST--
swoole_http2_server: request uri with query string
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
        $req->path = '/foo/bar?alpha=1&beta=two';
        Assert::greaterThan($cli->send($req), 0);

        /** @var Swoole\Http2\Response $response */
        $response = $cli->recv();
        $data = json_decode($response->data, true);

        Assert::same($data['request_uri'], '/foo/bar');
        Assert::same($data['path_info'], '/foo/bar');
        Assert::same($data['query_string'], 'alpha=1&beta=two');

        $pm->kill();
    });

    Swoole\Event::wait();
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);

    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });

    $http->on('request', function (Request $request, Response $response) {
        $response->end(json_encode([
            'request_uri' => $request->server['request_uri'],
            'path_info' => $request->server['path_info'],
            'query_string' => $request->server['query_string'] ?? '',
        ], JSON_UNESCAPED_SLASHES));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
