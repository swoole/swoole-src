--TEST--
swoole_http_server: parse chunked multipart headers split across chunks
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $boundary = 'swoole-chunked-multipart';
    $body = "--{$boundary}\r\n" .
        "Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n" .
        "--{$boundary}\r\n" .
        "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" .
        "Content-Type: text/plain\r\n\r\nfile-data\r\n" .
        "--{$boundary}--\r\n";
    $split = strpos($body, 'name="file"') + strlen('name="fi');
    $first = substr($body, 0, $split);
    $second = substr($body, $split);
    $request = "POST / HTTP/1.1\r\n" .
        "Host: localhost\r\n" .
        "Content-Type: multipart/form-data; boundary={$boundary}\r\n" .
        "Transfer-Encoding: chunked\r\n" .
        "Connection: close\r\n\r\n" .
        dechex(strlen($first)) . "\r\n{$first}\r\n" .
        dechex(strlen($second)) . "\r\n{$second}\r\n0\r\n\r\n";

    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    stream_set_timeout($socket, 3);
    Assert::same(fwrite($socket, $request), strlen($request));
    $response = stream_get_contents($socket);
    fclose($socket);
    $pm->kill();

    Assert::contains($response, '200 OK');
    $result = json_decode(explode("\r\n\r\n", $response, 2)[1], true);
    Assert::same($result, ['field' => 'value', 'name' => 'test.txt', 'content' => 'file-data', 'raw' => $body]);
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['http_parse_files' => true, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(json_encode([
            'field' => $request->post['field'] ?? null,
            'name' => $request->files['file']['name'] ?? null,
            'content' => isset($request->files['file']['tmp_name'])
                ? file_get_contents($request->files['file']['tmp_name'])
                : null,
            'raw' => $request->rawContent(),
        ]));
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
