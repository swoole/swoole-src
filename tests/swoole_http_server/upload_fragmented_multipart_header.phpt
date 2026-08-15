--TEST--
swoole_http_server: upload with fragmented multipart header
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $boundary = 'fragmented-boundary';
    $file = str_repeat('A', 4096);
    $body = "--{$boundary}\r\n";
    $body .= "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\n";
    $body .= "{$file}\r\n";
    $body .= "--{$boundary}\r\n";
    $body .= "Content-Disposition: form-data; name=\"field\"\r\n\r\n";
    $body .= "field-value\r\n";
    $body .= "--{$boundary}--\r\n";

    $headers = "POST / HTTP/1.1\r\n";
    $headers .= "Host: 127.0.0.1\r\n";
    $headers .= "Content-Type: multipart/form-data; boundary={$boundary}\r\n";
    $headers .= 'Content-Length: ' . strlen($body) . "\r\n";
    $headers .= "Connection: close\r\n\r\n";

    $split = strpos($body, 'name="field"') + strlen('name="fi');
    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $errstr, 1);
    Assert::notSame($socket, false);

    foreach ([$headers . substr($body, 0, $split), substr($body, $split)] as $data) {
        for ($offset = 0; $offset < strlen($data);) {
            $written = fwrite($socket, substr($data, $offset));
            Assert::greaterThan($written, 0);
            $offset += $written;
        }
        usleep(100000);
    }

    $response = stream_get_contents($socket);
    fclose($socket);
    Assert::contains($response, "200 OK");
    Assert::contains($response, "field-value:4096");
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'package_max_length' => 1024,
        'upload_max_filesize' => 8192,
    ]);
    $http->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end($request->post['field'] . ':' . filesize($request->files['file']['tmp_name']));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
