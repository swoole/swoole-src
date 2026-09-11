--TEST--
swoole_http_server: upload file without temporary directory
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$uploadTmpDir = sys_get_temp_dir() . '/swoole-upload-' . get_safe_random(8);

$pm->parentFunc = function () use ($pm) {
    $boundary = '------------------------d3f990cdce762596';
    $body = implode("\r\n", [
        "--$boundary",
        'Content-Disposition: form-data; name="file"; filename="test.txt"',
        'Content-Type: text/plain',
        '',
        'test',
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

    [, $body] = explode("\r\n\r\n", $response, 2);
    $files = json_decode($body, true);
    Assert::true(isset($files['file']));
    assert_upload_file($files['file'], '', 'test.txt', 'text/plain', 0, UPLOAD_ERR_NO_TMP_DIR);

    $pm->kill();
};

$pm->childFunc = function () use ($pm, $uploadTmpDir) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'log_file' => '/dev/null',
        'upload_tmp_dir' => $uploadTmpDir,
    ]);
    Assert::true(rmdir($uploadTmpDir));
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(json_encode($request->files));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
