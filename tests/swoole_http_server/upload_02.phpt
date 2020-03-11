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
    $length = mt_rand(100000, 200000);
    $content = "POST / HTTP/1.1\r\n" .
        "Host: local.swoole.com\r\n" .
        "Content-Type: multipart/form-data; boundary=Boundary+D80E45AE1BB1E1E1\r\n" .
        "Connection: keep-alive\r\n" .
        "Accept: */*\r\n" .
        "User-Agent: SCRM/1.0.1 (iPhone; iOS 10.3.3; Scale/2.00)\r\n" .
        "Accept-Language: zh-Hans-CN;q=1\r\n" .
        "Content-Length: {{content_length}}\r\n" .
        "\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"folder_id\"\r\n" .
        "\r\n" .
        "0\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"name\"\r\n" .
        "\r\n" .
        "IMG_0941(17).png\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"servers_id\"\r\n" .
        "\r\n" .
        "1000\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"size\"\r\n" .
        "\r\n" .
        "103972\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"token\"\r\n" .
        "\r\n" .
        "08ccbb0e11cb5cbc718c71fa7be2adfb\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"type\"\r\n" .
        "\r\n" .
        "0\r\n" .
        "--Boundary+D80E45AE1BB1E1E1\r\n" .
        "Content-Disposition: form-data; name=\"file\"; filename=\"IMG_0941(17).png\"\r\n" .
        "Content-Type: application/octet-stream\r\n\r\n" .
        "{{file_content}}\r\n" .
        "--Boundary+D80E45AE1BB1E1E1--\r\n";
    $content = content_hook_replace(
        $content, [
            'content_length' => $length,
            'file_content' => str_repeat(get_safe_random(1), $length - 718)
        ]
    );
    fwrite($sock, $content);
    stream_set_chunk_size($sock, 2 * 1024 * 1024);
    $data = fread($sock, 2 * 1024 * 1024);
    Assert::assert(!empty($data));
    $json = json_decode(explode("\r\n\r\n", $data, 2)[1], true);
    Assert::assert(is_array($json));
    Assert::true(isset($json['file']));
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(json_encode($request->files + $request->post));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
