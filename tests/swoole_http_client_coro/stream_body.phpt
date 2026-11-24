--TEST--
swoole_http_client_coro: stream bodies honor current positions and exact lengths with HTTP and HTTPS
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$data = str_repeat("binary\0\xff", 20000);
$file = tempnam(sys_get_temp_dir(), 'swoole-stream-body-');
file_put_contents($file, $data);
try {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_FILE);
    Coroutine\run(function () use ($file, $data) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            foreach ([$file, 'php://memory', 'php://temp/maxmemory:1024'] as $path) {
                foreach ([false, true] as $defer) {
                    $stream = fopen($path, $path === $file ? 'rb' : 'w+b');
                    if ($path !== $file) {
                        fwrite($stream, $data);
                    }
                    $cases = [[7, 0], [13, 1], [3, 65535], [9, 65536], [11, 65537], [17, null],
                        [strlen($data), null], [strlen($data) + 10, null]];
                    $listener = http_client_body_listener($ssl);
                    Coroutine::create(function () use ($listener, $ssl, $cases, $data) {
                        $peer = $listener->accept(5);
                        Assert::notSame($peer, false);
                        if ($ssl) {
                            Assert::true($peer->sslHandshake());
                        }
                        $buffer = '';
                        foreach ($cases as [$offset, $length]) {
                            $expected = substr($data, $offset, $length);
                            $request = http_client_body_headers($peer, $buffer);
                            Assert::same($request['length'], strlen($expected));
                            $hash = http_client_body_digest($peer, $buffer, $request['length']);
                            Assert::same($hash, hash('sha256', $expected));
                            http_client_body_reply($peer, $hash);
                        }
                        $peer->close();
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5, 'collect_stats' => true]);
                    $client->setDefer($defer);
                    $client->setHeaders(['Content-Length' => '999999']);
                    foreach ($cases as [$offset, $length]) {
                        // The position and inferred length are resolved when execute() starts, not in setData().
                        Assert::true($client->setData($stream, $length));
                        Assert::same(fseek($stream, $offset), 0);
                        $expected = substr($data, $offset, $length);
                        Assert::true($client->execute('/stream'));
                        if ($defer) {
                            Assert::true($client->recv());
                        }
                        Assert::same($client->body, hash('sha256', $expected));
                        Assert::same(ftell($stream), $offset + strlen($expected));
                        Assert::same($client->stats['upload_content_length'], strlen($expected));
                        Assert::same($client->stats['size_upload'], strlen($expected));
                        Assert::same($client->stats['request_size'], strlen($client->getHeaderOut()) + 4 + strlen($expected));
                    }
                    $client->close();
                    Assert::true(is_resource($stream));
                    fclose($stream);
                    $listener->close();
                }
            }
        }
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
