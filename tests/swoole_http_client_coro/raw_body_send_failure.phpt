--TEST--
swoole_http_client_coro: raw upload timeout, cancellation and peer close abandon the connection safely
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Event;

Assert::setThrowException(true);

Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach (['timeout', 'cancel', 'throw', 'peer-close'] as $case) {
            $listener = http_client_body_listener($ssl);
            $release = new Channel(1);
            $cid = Coroutine::getCid();
            Coroutine::create(function () use ($listener, $ssl, $release, $cid, $case) {
                $peer = $listener->accept(5);
                Assert::notSame($peer, false);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                Assert::notNull(http_client_body_headers($peer, $buffer));
                if ($case === 'peer-close') {
                    $peer->close();
                } else {
                    if ($case === 'cancel' || $case === 'throw') {
                        Event::defer(function () use ($cid, $case, $ssl) {
                            // Retire completed partial writes before cancelling the blocked upload (io_uring).
                            Coroutine::sleep(0.01);
                            Assert::true(Coroutine::cancel($cid, $case === 'throw'), $case . ' ssl:' . (int) $ssl);
                        });
                    }
                    $release->pop();
                    $peer->close();
                }
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
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 2, 'write_timeout' => $case === 'timeout' ? 0.05 : 2]);
            $thrown = false;
            try {
                Assert::false($client->post('/blocked', str_repeat('x', 16 * 1024 * 1024)));
            } catch (Coroutine\CanceledException $e) {
                $thrown = true;
            }
            Assert::same($thrown, $case === 'throw');
            Assert::false($client->connected);
            Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED);
            if ($case === 'timeout') {
                Assert::same($client->errCode, SOCKET_ETIMEDOUT);
            } elseif ($case === 'cancel' || $case === 'throw') {
                Assert::same($client->errCode, SOCKET_ECANCELED, $case . ' ssl:' . (int) $ssl);
            } else {
                Assert::notSame($client->errCode, 0, $case . ' ssl:' . (int) $ssl . ' ' . $client->errMsg);
            }
            $release->close();
            $client->set(['timeout' => 2, 'write_timeout' => 2]);
            Assert::true($client->post('/recovered', 'ok'));
            Assert::same($client->body, 'recovered');
            $client->close();
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
