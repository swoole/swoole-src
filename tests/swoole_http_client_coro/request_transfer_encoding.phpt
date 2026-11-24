--TEST--
swoole_http_client_coro: reject unsupported request transfer codings before sending headers in every body mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-transfer-coding-');
file_put_contents($file, 'contents');
try {
    Coroutine\run(function () use ($file) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            foreach (['none', 'string', 'form', 'stream', 'memory-part', 'file-part'] as $mode) {
                foreach (['chunked', 'gzip'] as $coding) {
                    $listener = http_client_body_listener($ssl);
                    Coroutine::create(function () use ($listener, $ssl) {
                        $peer = $listener->accept(5);
                        if ($ssl) {
                            Assert::true($peer->sslHandshake());
                        }
                        $buffer = '';
                        // The rejected request must not have put even its headers on this connection.
                        $request = http_client_body_headers($peer, $buffer);
                        Assert::contains($request['header'], 'POST /valid HTTP/1.1');
                        Assert::same($request['length'], 2);
                        Assert::same(http_client_body_digest($peer, $buffer, 2), hash('sha256', 'ok'));
                        http_client_body_reply($peer, 'valid', 200, true);
                        $peer->close();
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5]);
                    $stream = fopen('php://temp', 'w+b');
                    fwrite($stream, 'contents');
                    rewind($stream);
                    match ($mode) {
                        'string' => $client->setData('contents'),
                        'form' => $client->setData(['name' => 'value']),
                        'stream' => $client->setData($stream),
                        'memory-part' => $client->addData('contents', 'part'),
                        'file-part' => $client->addFile($file, 'part'),
                        default => null,
                    };
                    $client->setHeaders(['tRaNsFeR-EnCoDiNg' => $coding, 'Content-Length' => '999999']);
                    try {
                        $client->execute('/invalid');
                        throw new RuntimeException('Unsupported request framing should fail');
                    } catch (ValueError $error) {
                        Assert::contains($error->getMessage(), 'Transfer-Encoding');
                    }
                    Assert::same(ftell($stream), 0);
                    $client->setHeaders([]);
                    $client->uploadFiles = [];
                    Assert::true($client->post('/valid', 'ok'));
                    Assert::same($client->body, 'valid');
                    $client->close();
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
