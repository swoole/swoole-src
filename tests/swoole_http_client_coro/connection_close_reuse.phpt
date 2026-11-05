--TEST--
swoole_http_client_coro: connection close state belongs to a single exchange
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);

function connection_request(Client $client, string $path, bool $defer): string
{
    $client->setDefer($defer);
    Assert::true($client->get($path), $path);
    if ($defer) {
        Assert::true($client->connected);
        Assert::true($client->recv(), $path);
    }
    Assert::same($client->statusCode, 200);
    return $client->body;
}

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $port = $listener->getsockname()['port'];
    $connectionId = 0;
    $retryAttempts = 0;
    Coroutine::create(function () use ($listener, &$connectionId, &$retryAttempts) {
        while ($peer = $listener->accept(2)) {
            $id = (string) ++$connectionId;
            Coroutine::create(function () use ($peer, $id, &$retryAttempts) {
                $buffer = '';
                while (true) {
                    while (($end = strpos($buffer, "\r\n\r\n")) === false) {
                        $data = $peer->recv(8192, 2);
                        if ($data === false || $data === '') {
                            $peer->close();
                            return;
                        }
                        $buffer .= $data;
                    }
                    $request = substr($buffer, 0, $end);
                    $buffer = substr($buffer, $end + 4);
                    $path = explode(' ', $request, 3)[1];
                    $connection = match ($path) {
                        '/response-close' => "Connection: close\r\n",
                        '/response-token-close' => "Connection: keep-alive, cLoSe\r\n",
                        '/response-duplicate-close' => "Connection: close\r\nConnection: keep-alive\r\n",
                        '/response-prefix' => "Connection: close-extra\r\n",
                        '/response-keep-alive' => "Connection: keep-alive\r\n",
                        default => '',
                    };
                    $status = 200;
                    if ($path === '/retry' && $retryAttempts++ % 2 === 0) {
                        $status = 503;
                        $connection = "Connection: close\r\n";
                    }
                    $length = strlen($id);
                    $response = "HTTP/1.1 $status Status\r\n{$connection}Content-Length: $length\r\n\r\n$id";
                    Assert::same($peer->sendAll($response), strlen($response));
                    // Keep the peer open to test the client's policy independently of EOF detection.
                }
            });
        }
    });

    try {
        foreach ([false, true] as $defer) {
            foreach ([true, false] as $lowercase) {
                foreach (['/response-close', '/response-token-close', '/response-duplicate-close'] as $path) {
                    $client = new Client('127.0.0.1', $port);
                    $client->set(['timeout' => 2, 'lowercase_header' => $lowercase]);
                    $closedId = connection_request($client, $path, $defer);
                    Assert::false($client->connected, $path);
                    $id = connection_request($client, '/normal', $defer);
                    Assert::true($client->connected, $path);
                    Assert::notSame($id, $closedId);
                    Assert::same(connection_request($client, '/normal', $defer), $id);
                    $client->close();
                }

                foreach (['close', 'keep-alive, CLOSE', " keep-alive,\tclose "] as $value) {
                    $client = new Client('127.0.0.1', $port);
                    $client->set(['timeout' => 2, 'lowercase_header' => $lowercase]);
                    $client->setHeaders(['Connection' => $value]);
                    connection_request($client, '/response-keep-alive', $defer);
                    Assert::false($client->connected, $value);
                    $client->setHeaders([]);
                    $id = connection_request($client, '/normal', $defer);
                    Assert::true($client->connected, $value);
                    Assert::contains($client->getHeaderOut(), "Connection: keep-alive\r\n");
                    Assert::same(connection_request($client, '/normal', $defer), $id);
                    $client->close();
                }

                $client = new Client('127.0.0.1', $port);
                $client->set(['timeout' => 2, 'lowercase_header' => $lowercase]);
                $id = connection_request($client, '/response-prefix', $defer);
                Assert::true($client->connected);
                Assert::same(connection_request($client, '/normal', $defer), $id);
                $client->close();

                $client = new Client('127.0.0.1', $port);
                $client->set(['timeout' => 2]);
                $client->setDefer($defer);
                $client->setHeaders(['Connection' => 'close']);
                $client->setCookies(['token' => str_repeat('x', 4097)]);
                try {
                    $client->get('/normal');
                    Assert::true(false, 'Expected cookie validation to fail');
                } catch (Swoole\Coroutine\Http\Client\Exception $e) {
                    Assert::contains($e->getMessage(), 'cookie header is too large');
                }
                $client->setHeaders([]);
                $client->setCookies([]);
                $id = connection_request($client, '/normal', $defer);
                Assert::true($client->connected);
                Assert::same(connection_request($client, '/normal', $defer), $id);
                $client->close();

                $client = new Client('127.0.0.1', $port);
                $client->set(['timeout' => 2, 'keep_alive' => false]);
                connection_request($client, '/response-keep-alive', $defer);
                Assert::false($client->connected);
                Assert::contains($client->getHeaderOut(), "Connection: close\r\n");
                $client->set(['keep_alive' => true]);
                $id = connection_request($client, '/normal', $defer);
                Assert::true($client->connected);
                Assert::same(connection_request($client, '/normal', $defer), $id);
                $client->close();
            }
        }

        $client = new Client('127.0.0.1', $port);
        $client->set(['timeout' => 2, 'max_retries' => 1]);
        $id = connection_request($client, '/retry', false);
        Assert::same($retryAttempts, 2);
        Assert::true($client->connected);
        Assert::same(connection_request($client, '/normal', false), $id);
        $client->close();
    } finally {
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
