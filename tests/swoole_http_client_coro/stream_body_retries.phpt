--TEST--
swoole_http_client_coro: retry seekable streams from the original position and avoid replaying pipes
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
        foreach ([false, true] as $defer) {
            $listener = http_client_body_listener($ssl);
            [$source, $state] = HttpClientUploadStream::open(200000);
            fseek($source, 7);
            $length = 131073;
            $expected = hash('sha256', HttpClientUploadStream::bytes(7, $length));
            $statuses = $defer ? [502] : [502, 503, 200];
            Coroutine::create(function () use ($listener, $ssl, $statuses, $length, $expected) {
                foreach ($statuses as $status) {
                    $peer = $listener->accept(5);
                    Assert::notSame($peer, false);
                    if ($ssl) {
                        Assert::true($peer->sslHandshake());
                    }
                    $buffer = '';
                    $request = http_client_body_headers($peer, $buffer);
                    Assert::same($request['length'], $length);
                    Assert::same(http_client_body_digest($peer, $buffer, $length), $expected);
                    http_client_body_reply($peer, $expected, $status, true);
                    $peer->close();
                }
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 5, 'max_retries' => 2, 'collect_stats' => true]);
            $client->setDefer($defer);
            $client->setData($source, $length);
            // Pending configuration changes must not alter this request's retry source or length.
            $state->onStat = static fn () => $client->setData('pending');
            $state->onRead = static fn () => $client->setData('pending');
            Assert::true($client->execute('/retry'));
            if ($defer) {
                Assert::true($client->recv());
            }
            Assert::same($client->statusCode, $defer ? 502 : 200);
            Assert::same($client->body, $expected);
            Assert::same(ftell($source), 7 + $length);
            Assert::same($state->rewinds, $defer ? 0 : 2);
            Assert::same($client->stats['size_upload'], $length);
            $client->close();
            fclose($source);
            $listener->close();
        }
        foreach (['filtered', 'rewind-failed', 'exhausted'] as $case) {
            $length = 65537;
            $expected = hash('sha256', HttpClientUploadStream::bytes(0, $length));
            if ($case === 'filtered') {
                $source = fopen('php://temp', 'w+b');
                fwrite($source, 'filtered');
                rewind($source);
                stream_filter_append($source, 'convert.base64-encode', STREAM_FILTER_READ);
                $length = strlen(base64_encode('filtered'));
                $expected = hash('sha256', base64_encode('filtered'));
            } else {
                [$source, $state] = HttpClientUploadStream::open($length, true, $case !== 'rewind-failed');
            }
            $statuses = $case === 'exhausted' ? [502, 503] : [503];
            $listener = http_client_body_listener($ssl);
            Coroutine::create(function () use ($listener, $ssl, $length, $expected, $statuses) {
                foreach ($statuses as $status) {
                    $peer = $listener->accept(5);
                    Assert::notSame($peer, false);
                    if ($ssl) {
                        Assert::true($peer->sslHandshake());
                    }
                    $buffer = '';
                    $request = http_client_body_headers($peer, $buffer);
                    Assert::same($request['length'], $length);
                    Assert::same(http_client_body_digest($peer, $buffer, $length), $expected);
                    http_client_body_reply($peer, 'unavailable', $status, true);
                    $peer->close();
                }
            });
            $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
            $client->set(['timeout' => 1, 'max_retries' => 1]);
            $client->setData($source, $length);
            Assert::same($client->execute('/retry-limits'), $case === 'filtered');
            if ($case === 'rewind-failed') {
                Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SEND_FAILED);
                Assert::contains($client->errMsg, 'rewind');
            } else {
                Assert::same($client->statusCode, 503);
                Assert::same($client->body, 'unavailable');
            }
            if ($case === 'exhausted') {
                Assert::same($state->rewinds, 1);
            }
            $client->close();
            fclose($source);
            $listener->close();
        }
        if (PHP_OS_FAMILY === 'Windows') {
            continue;
        }
        // A pipe can provide a known byte count without supporting rewind.
        [$source, $writer] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
        fwrite($writer, 'pipe-body');
        fclose($writer);
        $listener = http_client_body_listener($ssl);
        Coroutine::create(function () use ($listener, $ssl) {
            $peer = $listener->accept(5);
            if ($ssl) {
                Assert::true($peer->sslHandshake());
            }
            $buffer = '';
            $request = http_client_body_headers($peer, $buffer);
            Assert::same($request['length'], 9);
            Assert::same(http_client_body_digest($peer, $buffer, 9), hash('sha256', 'pipe-body'));
            http_client_body_reply($peer, 'unavailable', 503, true);
            $peer->close();
        });
        $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
        $client->set(['timeout' => 1, 'max_retries' => 2]);
        $client->setData($source, 9);
        Assert::true($client->execute('/pipe'));
        Assert::same($client->statusCode, 503);
        Assert::same($client->body, 'unavailable');
        $client->close();
        fclose($source);
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
