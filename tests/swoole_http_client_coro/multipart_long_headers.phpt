--TEST--
swoole_http_client_coro: long multipart field names, filenames and content types are sent without truncation
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-long-part-');
$content = "file\0content";
file_put_contents($file, $content);
try {
    Coroutine\run(function () use ($file, $content) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            foreach (['addData', 'addFile'] as $method) {
                foreach ([2047, 2048, 3000] as $size) {
                    $field = str_repeat('f', $size);
                    $part = str_repeat('p', $size);
                    $filename = str_repeat('n', $size) . '.bin';
                    $type = 'application/' . str_repeat('x', $size);
                    $listener = http_client_body_listener($ssl);
                    Coroutine::create(function () use ($listener, $ssl, $field, $part, $filename, $type, $content) {
                        $peer = $listener->accept(5);
                        if ($ssl) {
                            Assert::true($peer->sslHandshake());
                        }
                        $buffer = '';
                        $request = http_client_body_headers($peer, $buffer);
                        Assert::same(preg_match('/boundary=([^\r\n]+)/', $request['header'], $match), 1);
                        $boundary = $match[1];
                        $expected = "--$boundary\r\nContent-Disposition: form-data; name=\"$field\"\r\n\r\nvalue\r\n"
                            . "--$boundary\r\nContent-Disposition: form-data; name=\"$part\"; filename=\"$filename\"\r\n"
                            . "Content-Type: $type\r\n\r\n$content\r\n--$boundary--\r\n";
                        Assert::same($request['length'], strlen($expected));
                        Assert::same(http_client_body_digest($peer, $buffer, $request['length']), hash('sha256', $expected));
                        http_client_body_reply($peer, 'complete');
                        $request = http_client_body_headers($peer, $buffer);
                        Assert::same($request['length'], 2);
                        Assert::same(http_client_body_digest($peer, $buffer, 2), hash('sha256', 'ok'));
                        http_client_body_reply($peer, 'next', 200, true);
                        $peer->close();
                    });
                    $client = new Client('127.0.0.1', $listener->getsockname()['port'], $ssl);
                    $client->set(['timeout' => 5]);
                    $client->setData([$field => 'value']);
                    Assert::true($client->$method($method === 'addFile' ? $file : $content, $part, $type, $filename));
                    Assert::true($client->execute('/upload'));
                    Assert::same($client->body, 'complete');
                    Assert::true($client->post('/after', 'ok'));
                    Assert::same($client->body, 'next');
                    $client->close();
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
