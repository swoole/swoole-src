--TEST--
swoole_http2_client_coro: trailing HEADERS frames are exposed on Response::$trailers
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
use Swoole\Http2\Response as Http2Response;

const BODY = 'Hello, World!';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        Assert::true($client->connect());

        // A response with a distinct trailing HEADERS frame: "trailers" holds only the trailing
        // headers, while "headers" still contains everything (backward compatibility).
        $request = new Http2Request;
        $request->path = '/with-trailers';
        Assert::greaterThan($client->send($request), 0);
        /** @var Http2Response $response */
        $response = $client->recv();
        Assert::same($response->data, BODY);
        Assert::true(property_exists($response, 'trailers'));
        Assert::isArray($response->trailers);
        Assert::same($response->trailers['x-status'] ?? null, '0');
        Assert::same($response->trailers['x-checksum'] ?? null, 'abc');
        // Initial response headers must NOT be duplicated into trailers.
        Assert::false(isset($response->trailers['content-type']));
        // ...but everything is still present in "headers" as before.
        Assert::same($response->headers['x-status'] ?? null, '0');
        Assert::same($response->headers['content-type'] ?? null, 'text/plain');

        // A plain response with no trailing HEADERS frame keeps the property at its NULL default.
        $request = new Http2Request;
        $request->path = '/no-trailers';
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::same($response->data, BODY);
        Assert::same($response->trailers, null);
        Assert::same($response->headers['content-type'] ?? null, 'text/plain');

        // A single HEADERS frame (END_STREAM, no DATA, no separate trailing frame). From the
        // HTTP/2 layer this is simply the initial response headers: there is no trailers frame,
        // so "trailers" stays NULL and any grpc-like metadata remains in "headers". Application
        // protocols such as gRPC interpret those themselves; Swoole stays protocol-agnostic.
        $request = new Http2Request;
        $request->path = '/single-headers-frame';
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::same($response->trailers, null);
        Assert::same($response->headers['x-status'] ?? null, '5');
        Assert::same($response->headers['x-message'] ?? null, 'not found');

        echo "DONE\n";
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
            case '/with-trailers':
                $response->header('content-type', 'text/plain');
                $response->trailer('x-status', '0');
                $response->trailer('x-checksum', 'abc');
                $response->end(BODY);
                break;
            case '/no-trailers':
                $response->header('content-type', 'text/plain');
                $response->end(BODY);
                break;
            case '/single-headers-frame':
                // No trailer(): a lone HEADERS frame carrying :status plus ordinary headers.
                $response->header('content-type', 'application/grpc');
                $response->header('x-status', '5');
                $response->header('x-message', 'not found');
                $response->end('');
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
DONE
