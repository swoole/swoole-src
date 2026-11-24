--TEST--
swoole_http_client_coro: retain raw bodies across blocked writes and requestBody replacement
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
        foreach ([false, true] as $defer) {
            $listener = http_client_body_listener($ssl);
            $drain = new Channel(1);
            $changed = false;
            $data = str_repeat("\0original\xff", 1024 * 1024);
            $size = strlen($data);
            $expected = hash('sha256', $data);
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 5, 'collect_stats' => true]);
            $client->setMethod('PUT');
            $client->setDefer($defer);
            $client->setData($data);
            Coroutine::create(function () use ($listener, $ssl, $client, $drain, &$data, &$changed, $size, $expected) {
                $peer = $listener->accept(5);
                Assert::notSame($peer, false);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                for ($i = 0; $i < 2; $i++) {
                    $request = http_client_body_headers($peer, $buffer);
                    if ($i === 0) {
                        Assert::same($request['length'], $size);
                        // The reader waits too, so this runs only after the large sender yields to the event loop.
                        Event::defer(function () use ($client, $drain, &$data, &$changed) {
                            $client->setData('replacement');
                            $data[0] = 'x';
                            $data = null;
                            $changed = true;
                            $drain->push(true);
                        });
                        $drain->pop();
                    } else {
                        Assert::same($request['length'], strlen('replacement'));
                    }
                    $hash = http_client_body_digest($peer, $buffer, $request['length']);
                    Assert::same($hash, $i === 0 ? $expected : hash('sha256', 'replacement'));
                    http_client_body_reply($peer, $hash);
                }
                $peer->close();
            });
            for ($i = 0; $i < 2; $i++) {
                Assert::true($client->execute($i === 0 ? '/original' : '/replacement'));
                if ($defer) {
                    Assert::true($client->recv());
                }
                Assert::same($client->body, $i === 0 ? $expected : hash('sha256', 'replacement'));
                Assert::true($changed);
                $length = $i === 0 ? $size : strlen('replacement');
                Assert::contains($client->getHeaderOut(), "Content-Length: $length");
                Assert::same($client->stats['upload_content_length'], $length);
                Assert::same($client->stats['size_upload'], $length);
                Assert::same($client->stats['request_size'], strlen($client->getHeaderOut()) + 4 + $length);
            }
            $client->close();
            Assert::contains($client->getHeaderOut(), 'PUT /replacement HTTP/1.1');
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
