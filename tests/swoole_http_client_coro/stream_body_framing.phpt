--TEST--
swoole_http_client_coro: zero-length, filtered, post and replaced streams use correct framing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';
require __DIR__ . '/../include/api/http_client_upload_stream.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        $raw = "filtered\0binary\xff";
        $expected = ['', base64_encode($raw), 'complete-post-body', 'replacement-body', 'referenced-body'];
        $listener = http_client_body_listener($ssl);
        Coroutine::create(function () use ($listener, $ssl, $expected) {
            $peer = $listener->accept(5);
            Assert::notSame($peer, false);
            if ($ssl) {
                Assert::true($peer->sslHandshake());
            }
            $buffer = '';
            foreach ($expected as $body) {
                $request = http_client_body_headers($peer, $buffer);
                Assert::same($request['length'], strlen($body));
                Assert::same(http_client_body_digest($peer, $buffer, $request['length']), hash('sha256', $body));
                http_client_body_reply($peer, hash('sha256', $body));
            }
            $peer->close();
        });
        $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
        $client->set(['timeout' => 5]);
        [$zero, $state] = HttpClientUploadStream::open(100, false);
        $client->setData($zero, 0);
        $client->setHeaders(['Transfer-Encoding' => 'chunked']);
        try {
            $client->execute('/invalid-framing');
            throw new RuntimeException('Transfer-Encoding should be rejected');
        } catch (ValueError $exception) {
            Assert::contains($exception->getMessage(), 'Transfer-Encoding');
        }
        $client->setHeaders([]);
        Assert::true($client->execute('/zero'));
        Assert::same($client->body, hash('sha256', ''));
        Assert::same($state->reads, 0);
        Assert::same(ftell($zero), 0);
        fclose($zero);

        $filtered = fopen('php://temp', 'w+b');
        fwrite($filtered, $raw);
        rewind($filtered);
        stream_filter_append($filtered, 'convert.base64-encode', STREAM_FILTER_READ);
        $client->setData($filtered);
        try {
            $client->execute('/unknown-filtered-length');
            throw new RuntimeException('Filtered length must be explicit');
        } catch (ValueError $exception) {
            Assert::contains($exception->getMessage(), 'specify $length');
        }
        $client->setData($filtered, strlen($expected[1]));
        Assert::true($client->execute('/filtered'));
        Assert::same($client->body, hash('sha256', $expected[1]));
        fclose($filtered);

        $post = fopen('php://temp', 'w+b');
        fwrite($post, $expected[2]);
        rewind($post);
        $client->setData($post, 1);
        Assert::true($client->post('/post', $post));
        Assert::same($client->body, hash('sha256', $expected[2]));
        Assert::same(ftell($post), strlen($expected[2]));
        $replacement = fopen('php://temp', 'w+b');
        fwrite($replacement, $expected[3]);
        rewind($replacement);
        $client->setData($post, 0);
        $client->requestBody = $replacement;
        Assert::true($client->execute('/replaced'));
        Assert::same($client->body, hash('sha256', $expected[3]));
        $referenced = fopen('php://temp', 'w+b');
        fwrite($referenced, $expected[4]);
        rewind($referenced);
        $client->requestBody = &$referenced;
        Assert::true($client->execute('/referenced'));
        Assert::same($client->body, hash('sha256', $expected[4]));
        $client->close();
        Assert::true(is_resource($post));
        Assert::true(is_resource($replacement));
        fclose($post);
        fclose($replacement);
        fclose($referenced);
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
