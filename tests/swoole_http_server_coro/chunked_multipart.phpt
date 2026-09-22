--TEST--
swoole_http_server_coro: parse chunked multipart data split across boundaries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Socket;
use Swoole\Http\Request;
use Swoole\Http\Response;

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $server->set(['http_parse_files' => true]);
    $handled = 0;
    $result = [];

    Coroutine::create(function () use ($server, &$handled, &$result) {
        $server->handle('/', function (Request $request, Response $response) use (&$handled, &$result) {
            $handled++;
            $result = [
                'field' => $request->post['field'] ?? null,
                'name' => $request->files['file']['name'] ?? null,
                'raw' => $request->rawContent(),
                'content' => isset($request->files['file']['tmp_name'])
                    ? file_get_contents($request->files['file']['tmp_name'])
                    : null,
            ];
            $response->end('OK');
        });
        $server->start();
    });
    Coroutine::sleep(0.001);

    $boundary = 'swoole-chunked-boundary';
    $fileContent = "prefix0\r\n\r\nsuffix";
    $body = "--{$boundary}\r\n" .
        "Content-Disposition: form-data; name=\"field\"\r\n\r\n" .
        "value\r\n" .
        "--{$boundary}\r\n" .
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" .
        "Content-Type: text/plain\r\n\r\n" .
        $fileContent . "\r\n" .
        "--{$boundary}--\r\n";

    // Split the first part header at a chunk boundary, the second at a receive boundary, and end another receive on
    // body bytes that look like a terminating chunk.
    $chunkBoundary = strpos($body, 'name="field"') + strlen('name="fi');
    $receiveBoundary = strpos($body, 'name="file"') + strlen('name="fi');
    $falseEnd = strpos($body, "0\r\n\r\n") + 5;
    $firstChunk = substr($body, 0, $chunkBoundary);
    $secondChunk = substr($body, $chunkBoundary);
    $receiveOffset = $receiveBoundary - $chunkBoundary;
    $falseEndOffset = $falseEnd - $chunkBoundary;
    $parts = [
        dechex(strlen($firstChunk)) . "\r\n{$firstChunk}\r\n" .
            dechex(strlen($secondChunk)) . "\r\n" . substr($secondChunk, 0, $receiveOffset),
        substr($secondChunk, $receiveOffset, $falseEndOffset - $receiveOffset),
        substr($secondChunk, $falseEndOffset) . "\r\n",
    ];
    $header = "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Type: multipart/form-data; boundary={$boundary}\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n";

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->connect('127.0.0.1', $server->port, -1));
    foreach ($parts as $index => $part) {
        $data = ($index === 0 ? $header : '') . $part;
        Assert::same($socket->sendAll($data), strlen($data));
        Coroutine::sleep(0.05);
        Assert::same($handled, 0);
    }
    Assert::same($socket->sendAll("0\r\n\r\n"), 5);

    $response = '';
    while (($data = $socket->recv()) !== '' && $data !== false) {
        $response .= $data;
    }
    $server->shutdown();

    Assert::contains($response, 'HTTP/1.1 200 OK');
    Assert::same($result['field'], 'value');
    Assert::same($result['name'], 'test.txt');
    Assert::same($result['raw'], $body);
    Assert::same($result['content'], $fileContent);
    Assert::same($handled, 1);

    echo "DONE\n";
});
?>
--EXPECT--
DONE
