--TEST--
swoole_http_server: chunked and pipeline request
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

const EOF = "EOF";

function connectHttpSocket(ProcessManager $pm, bool $eof = true): Swoole\Coroutine\Socket
{
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
    if ($eof) {
        Assert::true($socket->setProtocol([
            'open_eof_check' => true,
            'package_eof' => EOF,
        ]));
    }
    return $socket;
}

function sendAndClose(ProcessManager $pm, string $request): string
{
    $socket = connectHttpSocket($pm, false);
    Assert::same($socket->sendAll($request), strlen($request));

    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    return $response;
}

function sendMalformedChunkedRequest(ProcessManager $pm, string $body): string
{
    $request =
        "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" . $body;
    $socket = connectHttpSocket($pm, false);
    Assert::same($socket->sendAll($request), strlen($request));
    Assert::true($socket->shutdown(STREAM_SHUT_WR));

    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    return $response;
}

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $socket = connectHttpSocket($pm);
        $request =
            "POST /chunk HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Transfer-Encoding: chunked\r\n\r\n" .
            "5;foo=token;bar=\"a\\\"b\"\r\nhello\r\n" .
            "0\r\nX-Trailer: yes\r\n\r\n" .
            "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        Assert::same(getHttpBody($socket->recvPacket()), 'chunk:hello');
        Assert::same(getHttpBody($socket->recvPacket()), 'next');

        $socket = connectHttpSocket($pm);
        $request =
            "POST /chunk HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Transfer-Encoding: chunked\r\n\r\n" .
            "5\r\nhello\r\n0\r\nX-Split";
        Assert::same($socket->sendAll($request), strlen($request));
        usleep(1000);
        $request = "-Trailer: yes\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        Assert::same(getHttpBody($socket->recvPacket()), 'chunk:hello');

        $socket = connectHttpSocket($pm);
        $request =
            "POST /chunk HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Transfer-Encoding: chunked\r\n\r\n" .
            "5;foo=\"a\\";
        Assert::same($socket->sendAll($request), strlen($request));
        usleep(1000);
        $request = "b\"\r\nhello\r";
        Assert::same($socket->sendAll($request), strlen($request));
        usleep(1000);
        $request = "\n0\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        Assert::same(getHttpBody($socket->recvPacket()), 'chunk:hello');

        $socket = connectHttpSocket($pm);
        $request =
            "POST /length HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Length: 5\r\n\r\nhello" .
            "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
        Assert::same($socket->sendAll($request), strlen($request));
        Assert::same(getHttpBody($socket->recvPacket()), 'length:hello');
        Assert::same(getHttpBody($socket->recvPacket()), 'next');

        $request =
            "POST / HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Length: 0\r\n" .
            "Transfer-Encoding: chunked\r\n" .
            "Connection: close\r\n\r\n0\r\n\r\n";
        $response = sendAndClose($pm, $request);
        Assert::same(substr_count($response, 'HTTP/1.1 400 Bad Request'), 1);

        $request =
            "POST / HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Length: 18446744073709551615\r\n" .
            "Connection: close\r\n\r\n";
        $response = sendAndClose($pm, $request);
        Assert::contains($response, 'HTTP/1.1 413 Request Entity Too Large');

        // Preserve strict framing for malformed data terminators and chunk-size whitespace.
        foreach (["5\r\nhelloXX\r\n0\r\n\r\n", "5 \r\nhello\r\n0\r\n\r\n"] as $body) {
            $response = sendMalformedChunkedRequest($pm, $body);
            Assert::same(substr_count($response, 'HTTP/1.1 400 Bad Request'), 1);
        }

        $response = sendMalformedChunkedRequest($pm, "5\nhello\n0\n\n");
        Assert::same(substr_count($response, 'HTTP/1.1 400 Bad Request'), 1);
    });
    chunked_request($pm);
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null',
        // 'log_level' => SWOOLE_LOG_DEBUG,
        // 'trace_flags' => SWOOLE_TRACE_ALL,
        'http_compression' => false,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        switch ($request->server['request_uri']) {
        case '/chunk':
            $body = 'chunk:' . $request->rawContent();
            break;
        case '/length':
            $body = 'length:' . $request->rawContent();
            break;
        case '/next':
            $body = 'next';
            break;
        default:
            $body = $request->rawContent();
        }
        $response->end($body . EOF);
    });
    $http->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
SUCCESS
