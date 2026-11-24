--TEST--
swoole_http_client_coro: receive timeout restoration keeps a closed socket alive
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Coroutine::set(['log_level' => SWOOLE_LOG_WARNING]);
Coroutine\run(function () {
    foreach ([false, true] as $ssl) {
        foreach (['response', 'eof', 'timeout'] as $case) {
            $listener = http_client_body_listener($ssl);
            Coroutine::create(function () use ($listener, $ssl, $case) {
                $peer = $listener->accept(5);
                Assert::notSame($peer, false);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                Assert::notNull(http_client_body_headers($peer, $buffer));
                if ($case === 'response') {
                    http_client_body_reply($peer, 'OK', 200, true);
                } elseif ($case === 'timeout') {
                    Coroutine::sleep(0.1);
                }
                $peer->close();
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 2]);
            $client->setDefer(true);
            Assert::true($client->post('/', ''));
            // This differs from the socket's timeout and must be restored after recv() closes it.
            Assert::same($client->recv($case === 'timeout' ? 0.02 : 0.5), $case === 'response');
            Assert::false($client->connected);
            if ($case === 'response') {
                Assert::same($client->body, 'OK');
            } elseif ($case === 'timeout') {
                Assert::same($client->errCode, SOCKET_ETIMEDOUT);
            } else {
                Assert::notSame($client->errCode, 0);
            }
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
