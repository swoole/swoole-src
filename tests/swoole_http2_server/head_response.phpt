--TEST--
swoole_http2_server: a HEAD response carries GET's headers but no content, even with a trailer set (RFC 9110 9.3.2)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const BODY = '<h1>Hello Swoole.</h1>';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();
        $request = new Swoole\Http2\Request;
        $request->method = 'HEAD';
        $request->path = '/';
        Assert::assert($cli->send($request));
        $response = $cli->recv(5);
        // Same status and header fields the equivalent GET would send, including Content-Length ...
        Assert::same($response->statusCode, 200);
        Assert::same($response->headers['content-length'], (string) strlen(BODY));
        // ... but no content in the response body (the HEADERS frame ends the stream, no DATA frame).
        Assert::same((string) $response->data, '');
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        // A trailer has no content to follow on a HEAD response: the server must drop it and still
        // end the stream on the HEADERS frame (without that, the client blocks waiting for END_STREAM).
        $response->trailer('x-checksum', 'deadbeef');
        $response->end(BODY);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
