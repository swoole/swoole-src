--TEST--
swoole_http_server: upload files empty
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $boundary = "------------------------d3f990cdce762596";
    $body = implode("\r\n", [
        "--$boundary",
        'Content-Disposition: form-data; name="file1"; filename="empty.txt"',
        'Content-Type: text/plain',
        '',
        '',
        "--$boundary",
        'Content-Disposition: form-data; name="file2"; filename=""',
        'Content-Type: application/octet-stream',
        '',
        '',
        "--$boundary--",
        '',
    ]);
    $request = implode("\r\n", [
        'POST / HTTP/1.1',
        "Content-Type: multipart/form-data; boundary=$boundary",
        'Content-Length: ' . strlen($body),
        '',
        $body,
    ]);

    $sock = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($sock, $request);
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $response = fread($sock, 2 * 1024 * 1024);
    fclose($sock);
    [$header, $body] = explode("\r\n\r\n", $response);
    $json = json_decode($body, true);
    Assert::true(is_array($json));
    Assert::true(isset($json['file1']));
    assert_upload_file($json['file1'], '/tmp/swoole.upfile.fixture1', 'empty.txt', 'text/plain', 0, 0);

    Assert::true(isset($json['file2']));
    assert_upload_file($json['file2'], '', '', '', 0, 4);

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $files = $request->files;
        if (isset($files['file1']['tmp_name'])) {
            $files['file1']['tmp_name'] = '/tmp/swoole.upfile.fixture1';
        }
        $response->end(json_encode($files));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
