--TEST--
swoole_http_server: body pipeline request in base mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

const EOF = "EOF";

function sendPipelineRequest(ProcessManager $pm, string $request, array $expected): void
{
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $pm->getFreePort()));
    Assert::true($socket->setProtocol([
        'open_eof_check' => true,
        'package_eof' => EOF,
    ]));
    Assert::same($socket->sendAll($request), strlen($request));
    foreach ($expected as $body) {
        $response = $socket->recvPacket();
        Assert::notEmpty($response);
        Assert::same(explode("\r\n\r\n", $response, 2)[1], $body . EOF);
    }
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $next = "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
        $request =
            "POST /chunk HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Transfer-Encoding: chunked\r\n\r\n" .
            "5\r\nhello\r\n0\r\n\r\n" . $next;
        sendPipelineRequest($pm, $request, ['chunk:hello', 'next']);

        $request =
            "POST /length HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Content-Length: 5\r\n\r\nhello" . $next;
        sendPipelineRequest($pm, $request, ['length:hello', 'next']);
    });
    $pm->kill();
    echo "SUCCESS\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $uri = $request->server['request_uri'];
        $body = $uri === '/next' ? 'next' : substr($uri, 1) . ':' . $request->rawContent();
        $response->end($body . EOF);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
