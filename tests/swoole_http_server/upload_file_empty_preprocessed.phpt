--TEST--
swoole_http_server: preserve empty uploads during preprocessing
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $boundary = '------------------------d3f990cdce762596';
    $content = str_repeat('A', 80 * 1024);
    $body = implode("\r\n", [
        "--$boundary",
        'Content-Disposition: form-data; name="large"; filename="large.txt"',
        'Content-Type: text/plain',
        '',
        $content,
        "--$boundary",
        'Content-Disposition: form-data; name="empty"; filename=""',
        'Content-Type: application/octet-stream',
        '',
        '',
        "--$boundary--",
        '',
    ]);
    $request = implode("\r\n", [
        'POST / HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: close',
        "Content-Type: multipart/form-data; boundary=$boundary",
        'Content-Length: ' . strlen($body),
        '',
        $body,
    ]);

    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);
    [, $responseBody] = explode("\r\n\r\n", $response, 2);
    $files = json_decode($responseBody, true);

    Assert::same($files['large']['error'], UPLOAD_ERR_OK);
    Assert::same($files['large']['size'], strlen($content));
    Assert::same($files['empty']['error'], UPLOAD_ERR_NO_FILE);
    Assert::same($files['empty']['tmp_name'], '');

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'log_file' => '/dev/null',
        'package_max_length' => 64 * 1024,
        'upload_max_filesize' => 1024 * 1024,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(json_encode($request->files));
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
