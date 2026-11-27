--TEST--
swoole_http_client_coro: reject layered content codings before delivering data and preserve raw responses
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('zlib');
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Coroutine\run(function () {
    $plain = 'response content';
    $gzip = gzencode($plain);
    $doubleGzip = gzencode($gzip);
    $cases = [
        'double-gzip' => [['gzip, gzip'], $doubleGzip, '', false],
        'gzip' => [['gzip'], $gzip, $plain, true],
        'case-and-whitespace' => [["\tGZip\t"], $gzip, $plain, true],
        'empty-list-elements' => [[', gzip, ,'], $gzip, $plain, true],
        'empty-field' => [['', 'gzip', ''], $gzip, $plain, true],
        'mixed' => [['gzip, deflate'], gzcompress($gzip), '', false],
        'separate-fields' => [['gzip', 'gzip'], $doubleGzip, '', false],
        'unknown-outer' => [['gzip, custom'], $doubleGzip, '', false],
        'unknown-inner' => [['custom', 'gzip'], $doubleGzip, '', false],
        'gzip-prefix' => [['gzip-custom'], $gzip, $gzip, true],
        'deflate-prefix' => [['deflate-custom'], $gzip, $gzip, true],
        'brotli-prefix' => [['br-custom'], $gzip, $gzip, true],
        'zstd-prefix' => [['zstd-custom'], $gzip, $gzip, true],
        'unknown-single' => [['custom'], $plain, $plain, true],
    ];
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach ($cases as $name => [$encodings, $wire, $expected, $valid]) {
            foreach (['memory', 'callback', 'download', 'raw', 'raw-callback', 'raw-download'] as $mode) {
                foreach ([false, true] as $chunked) {
                    $raw = str_starts_with($mode, 'raw');
                    $callback = str_ends_with($mode, 'callback');
                    $download = str_ends_with($mode, 'download');
                    $listener = http_client_body_listener($ssl);
                    $done = new Coroutine\Channel(1);
                    Coroutine::create(function () use ($listener, $ssl, $encodings, $wire, $chunked, $done) {
                        for ($attempt = 0; $attempt < 2; $attempt++) {
                            $peer = $listener->accept(5);
                            Assert::notSame($peer, false);
                            if ($ssl) {
                                Assert::true($peer->sslHandshake());
                            }
                            $buffer = '';
                            http_client_body_headers($peer, $buffer);
                            if ($attempt === 0) {
                                $response = "HTTP/1.1 200 OK\r\nConnection: close\r\n";
                                foreach ($encodings as $encoding) {
                                    $response .= "Content-Encoding: $encoding\r\n";
                                }
                                if ($chunked) {
                                    $response .= "Transfer-Encoding: chunked\r\n\r\n";
                                    foreach (str_split($wire) as $byte) {
                                        $response .= "1\r\n$byte\r\n";
                                    }
                                    $response .= "0\r\n\r\n";
                                } else {
                                    $response .= 'Content-Length: ' . strlen($wire) . "\r\n\r\n$wire";
                                }
                                // Rejected headers can make the client close before the write completes.
                                $peer->sendAll($response);
                            } else {
                                http_client_body_reply($peer, 'recovered', 200, true);
                            }
                            $peer->close();
                        }
                        $done->push(true);
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5, 'body_decompression' => !$raw]);
                    $client->setData('');
                    $received = '';
                    $calls = 0;
                    if ($callback) {
                        $client->set(['write_func' => function ($client, $data) use (&$received, &$calls) {
                            $received .= $data;
                            $calls++;
                        }]);
                    }
                    $filename = tempnam(sys_get_temp_dir(), 'swoole-content-encoding-');
                    try {
                        $ok = $download ? $client->download('/encoded', $filename) : $client->execute('/encoded');
                        Assert::same($ok, $raw || $valid, $name . '/' . $mode);
                        if (!$ok) {
                            Assert::same($client->errCode, SWOOLE_ERROR_HTTP_INVALID_PROTOCOL);
                            Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
                            Assert::false($client->connected);
                            Assert::same($calls, 0);
                            Assert::same($received, '');
                        } else {
                            $actual = $download ? file_get_contents($filename) : ($callback ? $received : $client->body);
                            Assert::same($actual, $raw ? $wire : $expected, $name . '/' . $mode);
                        }
                        $received = '';
                        Assert::true($client->post('/recover', ''));
                        Assert::same($callback ? $received : $client->body, 'recovered');
                        Assert::true($done->pop(5));
                    } finally {
                        $client->close();
                        $listener->close();
                        if (file_exists($filename)) {
                            unlink($filename);
                        }
                    }
                }
            }
        }
    }

    // These headers describe a representation, but the response has no body to decode.
    foreach (['HEAD', '204', '304'] as $kind) {
        $listener = http_client_body_listener(false);
        $done = new Coroutine\Channel(1);
        Coroutine::create(function () use ($listener, $kind, $done) {
            $peer = $listener->accept(5);
            $buffer = '';
            http_client_body_headers($peer, $buffer);
            $status = $kind === 'HEAD' ? 200 : (int) $kind;
            $response = "HTTP/1.1 $status Status\r\nConnection: close\r\nContent-Encoding: gzip, gzip\r\n\r\n";
            Assert::same($peer->sendAll($response), strlen($response));
            $peer->close();
            $done->push(true);
        });
        $client = new Client('127.0.0.1', $listener->getsockname()['port']);
        $client->set(['timeout' => 5]);
        $client->setMethod($kind === 'HEAD' ? 'HEAD' : 'GET');
        $client->setData('');
        Assert::true($client->execute('/no-body'));
        Assert::same($client->body, '');
        Assert::same($client->statusCode, $kind === 'HEAD' ? 200 : (int) $kind);
        $client->close();
        Assert::true($done->pop(5));
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
