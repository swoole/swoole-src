--TEST--
swoole_http2_server: preserve explicit Content-Length
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

// A body that compresses far below its original size, so the compressed length is
// distinct from both the raw length and the stale explicit value.
$compressible_body = str_repeat('swoole compression payload ', 2048);
// A response the application has already gzip-encoded itself, with its own exact
// Content-Length. The server must not compress it a second time.
$pre_encoded_plain = str_repeat('event-stream payload ', 64);
$pre_encoded_gzip = gzencode($pre_encoded_plain);
$explicit_body = str_repeat('x', 100);
$chunk_one = str_repeat('a', 8192);
$chunk_two = str_repeat('b', 4096);
$stream_length = strlen($chunk_one) + strlen($chunk_two);

$pm = new ProcessManager;
$pm->parentFunc = function () use (
    $pm,
    $compressible_body,
    $pre_encoded_plain,
    $pre_encoded_gzip,
    $explicit_body,
    $chunk_one,
    $chunk_two,
    $stream_length
) {
    Coroutine\run(function () use (
        $pm,
        $compressible_body,
        $pre_encoded_plain,
        $pre_encoded_gzip,
        $explicit_body,
        $chunk_one,
        $chunk_two,
        $stream_length
    ) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), false);
        $client->set(['timeout' => 10]);
        Assert::true($client->connect());

        $fetch = function (string $path, string $method = 'GET', array $headers = []) use ($client) {
            $request = new Http2Request;
            $request->path = $path;
            $request->method = $method;
            if ($headers) {
                $request->headers = $headers;
            }
            Assert::greaterThan($client->send($request), 0);
            $response = $client->recv();
            Assert::notEmpty($response);
            return $response;
        };

        // An explicit Content-Length survives streamed writes and a bare end().
        $response = $fetch('/stream');
        Assert::same($response->statusCode, 200);
        Assert::same($response->data, $chunk_one . $chunk_two);
        Assert::same($response->headers['content-length'], (string) $stream_length);

        // The streamed length is kept even when the request advertises compression,
        // because a streamed body is never compressed.
        $response = $fetch('/stream', 'GET', ['accept-encoding' => 'gzip']);
        Assert::same($response->data, $chunk_one . $chunk_two);
        Assert::same($response->headers['content-length'], (string) $stream_length);
        Assert::false(isset($response->headers['content-encoding']));

        // HEAD preserves an explicit representation length with no body.
        $response = $fetch('/head-explicit', 'HEAD');
        Assert::same($response->statusCode, 200);
        Assert::same((string) $response->data, '');
        Assert::same($response->headers['content-length'], '12345');

        // Advertising compression must not discard HEAD metadata when there is no body to compress.
        $response = $fetch('/head-explicit', 'HEAD', ['accept-encoding' => 'gzip']);
        Assert::same((string) $response->data, '');
        Assert::same($response->headers['content-length'], '12345');

        // HEAD without an explicit length omits Content-Length instead of synthesizing zero.
        $response = $fetch('/head-empty', 'HEAD');
        Assert::same((string) $response->data, '');
        Assert::false(isset($response->headers['content-length']));

        // end($body) preserves the caller's exact wire value; the leading zeroes prove
        // the value was not re-synthesized from the body length.
        $response = $fetch('/end-explicit');
        Assert::same($response->data, $explicit_body);
        Assert::same($response->headers['content-length'], '0000100');

        // Accept-Encoding alone does not replace an explicit value when the body is below
        // the compression threshold.
        $response = $fetch('/end-explicit', 'GET', ['accept-encoding' => 'gzip']);
        Assert::same($response->data, $explicit_body);
        Assert::same($response->headers['content-length'], '0000100');
        Assert::false(isset($response->headers['content-encoding']));

        // end($body) without an explicit value still synthesizes the body length.
        $response = $fetch('/end-plain');
        Assert::same($response->data, 'hello');
        Assert::same($response->headers['content-length'], '5');

        // A negotiated-compression complete body ignores the stale explicit value and
        // reports the compressed length with Content-Encoding.
        $response = $fetch('/compress', 'GET', ['accept-encoding' => 'gzip']);
        Assert::same($response->data, $compressible_body);
        Assert::same($response->headers['content-encoding'], 'gzip');
        Assert::notSame($response->headers['content-length'], '999999');
        Assert::notSame($response->headers['content-length'], (string) strlen($compressible_body));

        // A response the application already encoded keeps its encoding and exact length and is
        // not compressed again, even though the request advertises gzip.
        $response = $fetch('/pre-encoded', 'GET', ['accept-encoding' => 'gzip']);
        Assert::same($response->data, $pre_encoded_plain);
        Assert::same($response->headers['content-encoding'], 'gzip');
        Assert::same($response->headers['content-length'], '000' . strlen($pre_encoded_gzip));

        // An empty explicit Content-Length suppresses the field rather than emitting an empty one.
        $response = $fetch('/empty-length');
        Assert::same($response->data, 'body');
        Assert::false(isset($response->headers['content-length']));

        // The connection remains usable for a final ordinary request.
        $response = $fetch('/plain');
        Assert::same($response->data, 'OK');

        $client->close();
    });
    $pm->kill();
};
$pm->childFunc = function () use (
    $pm,
    $compressible_body,
    $pre_encoded_gzip,
    $explicit_body,
    $chunk_one,
    $chunk_two,
    $stream_length
) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http_compression' => true,
        'http_compression_min_length' => 1024,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Request $request, Response $response) use (
        $compressible_body,
        $pre_encoded_gzip,
        $explicit_body,
        $chunk_one,
        $chunk_two,
        $stream_length
    ) {
        switch ($request->server['request_uri']) {
            case '/stream':
                $response->header('content-length', (string) $stream_length);
                $response->write($chunk_one);
                $response->write($chunk_two);
                $response->end();
                break;
            case '/head-explicit':
                $response->header('content-length', '12345');
                $response->end();
                break;
            case '/head-empty':
                $response->end();
                break;
            case '/end-explicit':
                $response->header('content-length', '0000100');
                $response->end($explicit_body);
                break;
            case '/end-plain':
                $response->end('hello');
                break;
            case '/compress':
                $response->header('content-length', '999999');
                $response->end($compressible_body);
                break;
            case '/pre-encoded':
                // Content-Length may be inserted before Content-Encoding; header order must
                // not affect whether the explicit value survives.
                $response->header('content-length', '000' . strlen($pre_encoded_gzip));
                $response->header('content-encoding', 'gzip');
                $response->end($pre_encoded_gzip);
                break;
            case '/empty-length':
                $response->header('content-length', '');
                $response->end('body');
                break;
            case '/plain':
                $response->end('OK');
                break;
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
