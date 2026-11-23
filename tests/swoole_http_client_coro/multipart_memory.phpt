--TEST--
swoole_http_client_coro: addData retains and sends the original string without full-size copies
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
        foreach ([false, true] as $mutate) {
            $listener = http_client_body_listener($ssl);
            $drain = new Channel(1);
            $pattern = "\0memory\xff";
            $data = str_repeat($pattern, 2 * 1024 * 1024);
            $size = strlen($data);
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 5]);
            $client->setMethod('POST');
            Coroutine::create(function () use ($listener, $ssl, $drain, $client, &$data, $pattern, $size, $mutate) {
                $peer = $listener->accept(5);
                if ($ssl) {
                    Assert::true($peer->sslHandshake());
                }
                $buffer = '';
                $request = http_client_body_headers($peer, $buffer);
                Assert::same(preg_match('/boundary=([^\r\n]+)/', $request['header'], $match), 1);
                $boundary = $match[1];
                $prefix = "--$boundary\r\nContent-Disposition: form-data; name=\"part\"; filename=\"memory.bin\"\r\n"
                    . "Content-Type: application/octet-stream\r\n\r\n";
                $suffix = "\r\n--$boundary--\r\n";
                Assert::same($request['length'], strlen($prefix) + $size + strlen($suffix));
                $hash = hash_init('sha256');
                hash_update($hash, $prefix);
                $block = str_repeat($pattern, 8192);
                for ($offset = 0; $offset < $size; $offset += strlen($block)) {
                    hash_update($hash, substr($block, 0, min(strlen($block), $size - $offset)));
                }
                hash_update($hash, $suffix);
                $expected = hash_final($hash);
                Event::defer(function () use ($client, &$data, $drain, $mutate) {
                    $client->uploadFiles = null;
                    if ($mutate) {
                        $data[0] = 'x';
                    }
                    $data = null;
                    $drain->push(true);
                });
                Assert::true($drain->pop(5));
                Assert::same(http_client_body_digest($peer, $buffer, $request['length']), $expected);
                http_client_body_reply($peer, 'complete', 200, true);
                $peer->close();
            });
            memory_reset_peak_usage();
            $baseline = memory_get_usage();
            Assert::true($client->addData($data, 'part', 'application/octet-stream', 'memory.bin'));
            Assert::lessThan(memory_get_usage() - $baseline, 2 * 1024 * 1024);
            Assert::true($client->execute('/upload'));
            Assert::same($client->body, 'complete');
            // Mutating a retained source intentionally exercises PHP's copy-on-write allocation.
            if (!$mutate) {
                Assert::lessThan(memory_get_peak_usage() - $baseline, 4 * 1024 * 1024);
            }
            Assert::null($data);
            $client->close();
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
