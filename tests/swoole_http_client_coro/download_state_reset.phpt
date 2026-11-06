--TEST--
swoole_http_client_coro: download state is cleared after failures and bodyless responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);

function serve_download_responses(Socket $listener, array $responses): void
{
    Coroutine::create(function () use ($listener, $responses) {
        foreach ($responses as $response) {
            $peer = $listener->accept(2);
            if ($peer === false) {
                return;
            }
            $request = '';
            while (!str_contains($request, "\r\n\r\n")) {
                $data = $peer->recv(8192, 2);
                if ($data === false || $data === '') {
                    $peer->close();
                    return;
                }
                $request .= $data;
            }
            if ($response === null) {
                // The client times out and closes; no fixed server sleep is needed.
                Assert::same($peer->recv(1, 2), '');
            } else {
                Assert::same($peer->sendAll($response), strlen($response));
            }
            $peer->close();
        }
    });
}

Coroutine\run(function () {
    $body = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 7\r\n\r\npayload";
    $cases = [
        'empty-path' => [],
        'connect-failure' => [],
        'cookie-validation' => [],
        'empty-response' => ["HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"],
        'no-content' => ["HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"],
        'receive-timeout' => [null],
        'invalid-response' => ["INVALID RESPONSE\r\n\r\n"],
        'complete-download' => [$body],
    ];

    foreach ([false, true] as $defer) {
        foreach ([0, 8] as $offset) {
            foreach ($cases as $name => $responses) {
                $filename = tempnam(sys_get_temp_dir(), 'swoole-download-');
                file_put_contents($filename, 'original');
                $listener = new Socket(AF_INET, SOCK_STREAM, 0);
                Assert::true($listener->bind('127.0.0.1', 0));
                if ($name !== 'connect-failure') {
                    Assert::true($listener->listen());
                    serve_download_responses($listener, [...$responses, $body]);
                }
                $client = new Client('127.0.0.1', $listener->getsockname()['port']);
                $client->set([
                    'connect_timeout' => 0.05,
                    'timeout' => $name === 'receive-timeout' ? 0.05 : 2,
                ]);
                $client->setDefer($defer);
                try {
                    if ($name === 'cookie-validation') {
                        $client->setCookies(['token' => str_repeat('x', 4097)]);
                        try {
                            $client->download('/', $filename, $offset);
                            Assert::true(false, 'Expected cookie validation to fail');
                        } catch (Swoole\Coroutine\Http\Client\Exception $e) {
                            Assert::contains($e->getMessage(), 'cookie header is too large');
                        }
                        $client->setCookies([]);
                    } else {
                        $result = $client->download($name === 'empty-path' ? '' : '/', $filename, $offset);
                        if ($defer && $responses !== []) {
                            Assert::true($result, $name);
                            Assert::same($client->downloadFile, $filename);
                            Assert::same($client->downloadOffset, $offset);
                            $result = $client->recv();
                        }
                        Assert::same($result, in_array($name, ['empty-response', 'no-content', 'complete-download']), $name);
                    }

                    Assert::null($client->downloadFile, $name);
                    Assert::same($client->downloadOffset, 0, $name);
                    if ($name === 'connect-failure') {
                        Assert::true($listener->listen());
                        serve_download_responses($listener, [$body]);
                    }
                    $expectedFile = $name === 'complete-download'
                        ? ($offset === 0 ? 'payload' : 'originalpayload')
                        : 'original';
                    Assert::same(file_get_contents($filename), $expectedFile, $name);
                    $client->setDefer(false);
                    $client->set(['timeout' => 2]);
                    Assert::true($client->get('/ordinary-get'), $name);
                    Assert::same($client->body, 'payload', $name);
                    Assert::same(file_get_contents($filename), $expectedFile, $name);
                } finally {
                    $client->close();
                    $listener->close();
                    unlink($filename);
                }
            }
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
