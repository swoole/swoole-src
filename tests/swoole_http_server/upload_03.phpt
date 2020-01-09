--TEST--
swoole_http_server: upload raw
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $sock = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    $boundary = "Boundary+D80E45AE1BB1E1E1";
    $body = implode("\r\n", [
        "--$boundary\r\nContent-Disposition: form-data; name=\"folder_id\"\r\n\r\n999999955",
        "--$boundary\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\n" . str_repeat('A', rand(100, 200)),
        "--$boundary--"
    ]);
    $body .= "\r\n";
    $len = strlen($body);
    $data = implode("\r\n", [
        "POST /file_service/v3/file/upload_do HTTP/1.1",
        "Content-Type: multipart/form-data; boundary=$boundary; error=bad",
        "Content-Length: $len",
        "\r\n",
        $body,
    ]);
    fwrite($sock, $data);
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $data = fread($sock, 2 * 1024 * 1024);
    Assert::assert(!empty($data));
    $json = json_decode(explode("\r\n\r\n", $data, 2)[1], true);
    Assert::assert(is_array($json));
    Assert::true(isset($json['folder_id']));
    Assert::true(isset($json['name']));
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);

    $http->set(['log_file' => '/dev/null']);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(json_encode($request->post));
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
