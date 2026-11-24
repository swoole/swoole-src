--TEST--
swoole_http_client_coro: stream uploads send before reading everything and use bounded memory
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

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        $size = 32 * 1024 * 1024;
        [$source, $state] = HttpClientUploadStream::open($size);
        $state->fragment = 4093;
        $received = new Channel(1);
        $listener = http_client_body_listener($ssl);
        $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
        $client->set(['timeout' => 5]);
        $client->setData($source);
        $state->onRead = function ($state) use ($received, $client, &$source) {
            if ($state->position >= 65536 && $source !== null) {
                $client->setData('next');
                $source = null;
                // A reader that first loads the entire source cannot pass this handshake.
                Assert::true($received->pop(5));
            }
        };
        Coroutine::create(function () use ($listener, $ssl, $state, $received, $size) {
            $peer = $listener->accept(5);
            Assert::notSame($peer, false);
            if ($ssl) {
                Assert::true($peer->sslHandshake());
            }
            $buffer = '';
            $request = http_client_body_headers($peer, $buffer);
            Assert::same($request['length'], $size);
            while (strlen($buffer) < 65536) {
                $chunk = $peer->recv(65536 - strlen($buffer), 5);
                Assert::notSame($chunk, false);
                Assert::notSame($chunk, '');
                $buffer .= $chunk;
            }
            Assert::lessThan($state->position, $size);
            $received->push(true);
            http_client_body_reply($peer, http_client_body_digest($peer, $buffer, $size));
            $request = http_client_body_headers($peer, $buffer);
            Assert::same($request['length'], 4);
            Assert::same(http_client_body_digest($peer, $buffer, 4), hash('sha256', 'next'));
            http_client_body_reply($peer, 'next', 200, true);
            $peer->close();
        });
        $hash = hash_init('sha256');
        for ($offset = 0; $offset < $size; $offset += 65536) {
            hash_update($hash, HttpClientUploadStream::bytes($offset, min(65536, $size - $offset)));
        }
        $expected = hash_final($hash);
        memory_reset_peak_usage();
        $baseline = memory_get_usage();
        Assert::true($client->execute('/incremental'));
        Assert::same($client->body, $expected);
        Assert::lessThan(memory_get_peak_usage() - $baseline, 4 * 1024 * 1024);
        Assert::lessThanEq($state->maxRead, 65536);
        Assert::greaterThan($state->reads, 100);
        Assert::true($state->closed);
        Assert::true($client->execute('/next'));
        Assert::same($client->body, 'next');
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
