--TEST--
swoole_http_client_coro: reject corrupt or incomplete compressed responses in memory, callbacks and downloads
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
require __DIR__ . '/../include/http_compression_fixture.inc';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
Coroutine\run(function () {
    [$plain, $encoded] = http_compression_fixture();
    $encoded['raw-deflate'] = gzdeflate($plain);
    $cases = [];
    foreach ($encoded as $name => $wire) {
        $encoding = $name === 'raw-deflate' ? 'deflate' : $name;
        $cases[$name . '-valid'] = [$encoding, $wire, $plain, true];
        $cases[$name . '-truncated'] = [$encoding, substr($wire, 0, -1), $plain, false];
        $cases[$name . '-invalid'] = [$encoding, 'invalid', $plain, false];
        $cases[$name . '-trailing'] = [$encoding, $wire . 'garbage', $plain, false];
    }
    $crc = $encoded['gzip'];
    $crc[strlen($crc) - 8] = chr(ord($crc[strlen($crc) - 8]) ^ 0xff);
    $cases['gzip-crc'] = ['gzip', $crc, $plain, false];
    $cases['gzip-members'] = ['gzip', $encoded['gzip'] . $encoded['gzip'], $plain . $plain, true];
    $cases['gzip-second-member-truncated'] = ['gzip', $encoded['gzip'] . substr($encoded['gzip'], 0, -1), $plain . $plain, false];
    $cases['gzip-empty'] = ['gzip', gzencode(''), '', true];
    $cases['gzip-no-stream'] = ['gzip', '', '', false];
    $large = str_repeat('large-body-', 200000);
    $cases['gzip-large'] = ['gzip', gzencode($large), $large, true];
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
        foreach ($cases as $name => [$encoding, $wire, $expected, $valid]) {
            $modes = $encoding === 'gzip' ? ['memory', 'callback', 'download', 'raw'] : ['memory'];
            foreach ($modes as $mode) {
                foreach ([false, true] as $chunked) {
                    if ($name === 'gzip-large' && $chunked) {
                        continue;
                    }
                    $listener = http_client_body_listener($ssl);
                    Coroutine::create(function () use ($listener, $ssl, $encoding, $wire, $chunked) {
                        for ($attempt = 0; $attempt < 2; $attempt++) {
                            $peer = $listener->accept(5);
                            Assert::notSame($peer, false);
                            if ($ssl) {
                                Assert::true($peer->sslHandshake());
                            }
                            $buffer = '';
                            http_client_body_headers($peer, $buffer);
                            if ($attempt === 0) {
                                $headers = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Encoding: $encoding\r\n";
                                if ($chunked) {
                                    $framed = '';
                                    foreach (str_split($wire) as $byte) {
                                        $framed .= "1\r\n$byte\r\n";
                                    }
                                    $response = $headers . "Transfer-Encoding: chunked\r\n\r\n" . $framed . "0\r\n\r\n";
                                } else {
                                    $response = $headers . 'Content-Length: ' . strlen($wire) . "\r\n\r\n" . $wire;
                                }
                                // A malformed stream may make the client close while the response is being written.
                                $peer->sendAll($response);
                            } else {
                                http_client_body_reply($peer, 'recovered', 200, true);
                            }
                            $peer->close();
                        }
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5]);
                    $client->setData('');
                    $received = '';
                    if ($mode === 'callback') {
                        $client->set(['write_func' => function ($client, $data) use (&$received) {
                            $received .= $data;
                        }]);
                    } elseif ($mode === 'raw') {
                        $client->set(['body_decompression' => false]);
                    }
                    $filename = tempnam(sys_get_temp_dir(), 'swoole-compression-integrity-');
                    try {
                        $ok = $mode === 'download' ? $client->download('/compressed', $filename) : $client->execute('/compressed');
                        Assert::same($ok, $mode === 'raw' || $valid, $name . '/' . $mode);
                        if (!$ok) {
                            Assert::same($client->errCode, SWOOLE_ERROR_HTTP_INVALID_PROTOCOL);
                            Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
                            Assert::false($client->connected);
                            if ($mode === 'callback') {
                                Assert::true(str_starts_with($expected, $received));
                            }
                        } elseif ($mode === 'download') {
                            Assert::same(file_get_contents($filename), $expected);
                        } elseif ($mode === 'callback') {
                            Assert::same($received, $expected);
                        } else {
                            Assert::same($client->body, $mode === 'raw' ? $wire : $expected);
                        }
                        $received = '';
                        Assert::true($client->post('/recover', ''));
                        Assert::same($mode === 'callback' ? $received : $client->body, 'recovered');
                    } finally {
                        $client->close();
                        $listener->close();
                        unlink($filename);
                    }
                }
            }
        }
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
