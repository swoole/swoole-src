--TEST--
swoole_http_client_coro: raw string uploads do not allocate another full body
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
memory_limit=96M
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);

Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        $listener = http_client_body_listener($ssl);
        Coroutine::create(function () use ($listener, $ssl) {
            $peer = $listener->accept(5);
            Assert::notSame($peer, false);
            if ($ssl) {
                Assert::true($peer->sslHandshake());
            }
            $buffer = '';
            $request = http_client_body_headers($peer, $buffer);
            $hash = http_client_body_digest($peer, $buffer, $request['length']);
            http_client_body_reply($peer, $hash, 200, true);
            $peer->close();
        });
        $data = str_repeat("\0binary\xff", 2 * 1024 * 1024);
        $hash = hash('sha256', $data);
        memory_reset_peak_usage();
        $baseline = memory_get_usage();
        $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
        $client->set(['timeout' => 5]);
        Assert::true($client->post('/upload', $data));
        Assert::same($client->body, $hash);
        // Leave room for TLS, parsers and bounded read buffers, but not another 16 MiB string.
        Assert::lessThan(memory_get_peak_usage() - $baseline, 4 * 1024 * 1024);
        $client->close();
        $listener->close();
        unset($client, $data);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
