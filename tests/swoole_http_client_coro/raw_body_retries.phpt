--TEST--
swoole_http_client_coro: raw bodies survive empty uploads and 502/503 retries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);

Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach (['', '0', "a\0b\xff", str_repeat('payload', 32768)] as $body) {
            $listener = http_client_body_listener($ssl);
            $hash = hash('sha256', $body);
            Coroutine::create(function () use ($listener, $ssl, $body, $hash) {
                foreach ([502, 503, 200] as $status) {
                    $peer = $listener->accept(5);
                    Assert::notSame($peer, false);
                    if ($ssl) {
                        Assert::true($peer->sslHandshake());
                    }
                    $buffer = '';
                    $request = http_client_body_headers($peer, $buffer);
                    Assert::same($request['length'], strlen($body));
                    Assert::same(http_client_body_digest($peer, $buffer, $request['length']), $hash);
                    http_client_body_reply($peer, $hash, $status, true);
                    $peer->close();
                }
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 5, 'max_retries' => 2, 'collect_stats' => true]);
            $client->setHeaders(['Content-Type' => 'application/octet-stream', 'Content-Length' => '999999']);
            Assert::true($client->post('/retry', $body));
            Assert::same($client->statusCode, 200);
            Assert::same($client->body, $hash);
            Assert::contains($client->getHeaderOut(), 'Content-Length: ' . strlen($body));
            Assert::same($client->stats['upload_content_length'], strlen($body));
            Assert::same($client->stats['size_upload'], strlen($body));
            $client->close();
            $listener->close();
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
