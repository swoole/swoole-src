--TEST--
swoole_http_server: chunked package max length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

const PACKAGE_MAX_LENGTH = 100001;

function make_chunked_request(string $path, string $body): string
{
    return "POST {$path} HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        dechex(strlen($body)) . "\r\n{$body}\r\n0\r\n\r\n";
}

function send_chunked_request(ProcessManager $pm, string $request): string
{
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
    Assert::same($socket->sendAll($request), strlen($request));

    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    return $response;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $body = str_repeat('0123456789abcdef', 5625);
        $request = make_chunked_request('/below', $body);
        Assert::lessThan(strlen($request), PACKAGE_MAX_LENGTH);

        $response = send_chunked_request($pm, $request);
        Assert::contains($response, 'HTTP/1.1 200 OK');
        Assert::same(explode("\r\n\r\n", $response, 2)[1], strlen($body) . ':' . md5($body));

        $exactBody = str_repeat('E', PACKAGE_MAX_LENGTH);
        $overhead = strlen(make_chunked_request('/exact', $exactBody)) - strlen($exactBody);
        $exactBody = str_repeat('E', PACKAGE_MAX_LENGTH - $overhead);
        $request = make_chunked_request('/exact', $exactBody);
        Assert::same(strlen($request), PACKAGE_MAX_LENGTH);

        $response = send_chunked_request($pm, $request);
        Assert::contains($response, 'HTTP/1.1 200 OK');
        Assert::same(explode("\r\n\r\n", $response, 2)[1], strlen($exactBody) . ':' . md5($exactBody));

        $overhead = strlen(make_chunked_request('/above', $exactBody)) - strlen($exactBody);
        $aboveBody = str_repeat('X', PACKAGE_MAX_LENGTH + 1 - $overhead);
        $request = make_chunked_request('/above', $aboveBody);
        Assert::same(strlen($request), PACKAGE_MAX_LENGTH + 1);

        // Preserve rejection while ensuring the declared chunk cannot consume allocator padding.
        $response = send_chunked_request($pm, $request);
        Assert::contains($response, 'HTTP/1.1 413 Request Entity Too Large');
    });
    echo "SUCCESS";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'package_max_length' => PACKAGE_MAX_LENGTH,
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $body = $request->rawContent();
        $response->end(strlen($body) . ':' . md5($body));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
