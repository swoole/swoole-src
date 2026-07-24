--TEST--
swoole_http2_server: trailers after streamed writes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;
use Swoole\Http2\Request as Http2Request;

const BODY = 'Hello, World!';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        Assert::true($client->connect());

        // A streamed response without trailers still terminates with END_STREAM DATA.
        $request = new Http2Request;
        $request->path = '/stream-no-trailer';
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::same($response->data, BODY);
        Assert::false(isset($response->headers['grpc-status']));

        // Keep the streamed-write regression last so the controls run first.
        foreach (['/final-chunk-trailer', '/body-trailer', '/stream-then-trailer'] as $path) {
            $request = new Http2Request;
            $request->path = $path;
            Assert::greaterThan($client->send($request), 0);
            $response = $client->recv();
            Assert::same($response->data, BODY);
            Assert::same($response->headers['grpc-status'] ?? null, '0');
            Assert::same($response->headers['grpc-message'] ?? null, 'ok');
        }

        // The connection stays usable for an ordinary request afterwards.
        $request = new Http2Request;
        $request->path = '/plain';
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::same($response->data, 'OK');
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) {
        switch ($request->server['request_uri']) {
            case '/stream-then-trailer':
                $response->trailer('grpc-status', '0');
                $response->trailer('grpc-message', 'ok');
                $response->write('Hello, ');
                $response->write('World!');
                $response->end();
                break;
            case '/final-chunk-trailer':
                $response->trailer('grpc-status', '0');
                $response->trailer('grpc-message', 'ok');
                $response->write('Hello, ');
                $response->end('World!');
                break;
            case '/body-trailer':
                $response->trailer('grpc-status', '0');
                $response->trailer('grpc-message', 'ok');
                $response->end('Hello, World!');
                break;
            case '/stream-no-trailer':
                $response->write('Hello, ');
                $response->write('World!');
                $response->end();
                break;
            default:
                $response->end('OK');
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
