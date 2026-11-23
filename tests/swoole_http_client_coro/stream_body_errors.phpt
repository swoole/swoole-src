--TEST--
swoole_http_client_coro: stream read failures, closure and reentrancy preserve connection safety
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';
require __DIR__ . '/../include/api/http_client_upload_stream.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Event;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach (['short', 'no-progress', 'throw', 'close-source', 'close-client', 'nested'] as $case) {
            $listener = http_client_body_listener($ssl);
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 5]);
            [$source, $state] = HttpClientUploadStream::open(16 * 1024 * 1024, false);
            $client->setData($source, $state->length);
            $gate = new Channel(1);
            $done = new Channel(1);
            if ($case === 'short') {
                $state->available = 65537;
            } elseif ($case === 'no-progress') {
                $state->fragment = 0;
            } elseif ($case === 'throw') {
                $state->onRead = function ($state) {
                    if ($state->position > 0) {
                        throw new RuntimeException('source-read-failed');
                    }
                };
            } elseif ($case === 'close-client') {
                $state->onRead = fn () => $client->close();
            } elseif ($case === 'nested') {
                $state->onRead = function ($state) use ($client) {
                    $state->onRead = null;
                    try {
                        $client->execute('/nested');
                        throw new RuntimeException('Nested execute should fail');
                    } catch (Error $error) {
                        Assert::contains($error->getMessage(), 'already sending');
                    }
                };
            }
            Coroutine::create(function () use ($listener, $ssl, $case, $source, $state, $gate, $done) {
                $peer = $listener->accept(5);
                Assert::notSame($peer, false);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                $request = http_client_body_headers($peer, $buffer);
                Assert::same($request['length'], $state->length);
                if ($case === 'close-source') {
                    Event::defer(function () use ($source, $gate) {
                        fclose($source);
                        $gate->push(true);
                    });
                    Assert::true($gate->pop(5));
                }
                if ($case === 'nested') {
                    http_client_body_reply($peer, http_client_body_digest($peer, $buffer, $request['length']), 200, true);
                } else {
                    $received = strlen($buffer);
                    while (($chunk = $peer->recv(65536, 5)) !== '') {
                        Assert::notSame($chunk, false);
                        $received += strlen($chunk);
                    }
                    Assert::lessThan($received, $request['length']);
                }
                $peer->close();
                if ($case !== 'nested') {
                    $peer = $listener->accept(5);
                    Assert::notSame($peer, false);
                    if ($ssl) {
                        Assert::true($peer->sslHandshake());
                    }
                    $buffer = '';
                    $request = http_client_body_headers($peer, $buffer);
                    Assert::same($request['length'], 2);
                    Assert::same(http_client_body_digest($peer, $buffer, 2), hash('sha256', 'ok'));
                    http_client_body_reply($peer, 'recovered', 200, true);
                    $peer->close();
                }
                $done->push(true);
            });
            $exception = null;
            try {
                Assert::same($client->execute('/upload'), $case === 'nested');
            } catch (Throwable $error) {
                $exception = $error;
            }
            if ($case === 'throw') {
                Assert::isInstanceOf($exception, RuntimeException::class);
                Assert::same($exception->getMessage(), 'source-read-failed');
            } elseif ($case === 'close-source') {
                Assert::isInstanceOf($exception, TypeError::class);
            } else {
                Assert::null($exception);
            }
            if ($case !== 'nested') {
                Assert::false($client->connected);
                Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED);
                Assert::notSame($client->errCode, 0);
                Assert::true($client->post('/recover', 'ok'));
                Assert::same($client->body, 'recovered');
            }
            Assert::true($done->pop(5));
            if (is_resource($source)) {
                fclose($source);
            }
            $client->close();
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
