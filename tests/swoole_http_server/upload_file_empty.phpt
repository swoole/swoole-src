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

    $result = ltrim(strstr($response, "\r\n\r\n"));
    echo "$result\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
    $http->set([
        'log_file' => '/dev/null'
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $files = $request->files;
        if (isset($files['file1']['tmp_name'])) {
            $files['file1']['tmp_name'] = '/tmp/swoole.upfile.fixture1';
        }
        $response->end(var_export($files, true));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
array (
  'file1' => 
  array (
    'name' => 'empty.txt',
    'type' => 'text/plain',
    'tmp_name' => '/tmp/swoole.upfile.fixture1',
    'error' => 0,
    'size' => 0,
  ),
  'file2' => 
  array (
    'name' => '',
    'type' => '',
    'tmp_name' => '',
    'error' => 4,
    'size' => 0,
  ),
)
