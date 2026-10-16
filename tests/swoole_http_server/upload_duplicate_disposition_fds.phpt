--TEST--
swoole_http_server: duplicate file dispositions do not leak descriptors
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!is_dir('/proc/self/fd')) {
    exit('skip requires /proc/self/fd');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
function send_review_request($pm, $body, $boundary = 'review-boundary')
{
    $headers = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary={$boundary}\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
    $s       = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $e, $m, 2);
    stream_set_timeout($s, 2);
    // The duplicate header can be rejected before its declared file body is received.
    $wireBody = str_contains($body, 'name="second"; filename="other.txt"')
        ? substr($body, 0, strpos($body, "\r\n\r\n") + 4)
        : $body;
    $data = $headers . $wireBody;
    for ($offset = 0; $offset < strlen($data);) {
        $n = @fwrite($s, substr($data, $offset));
        if (!$n) {
            break;
        }
        $offset += $n;
    }
    $out = stream_get_contents($s);
    fclose($s);
    return strtok($out, "\r\n");
}
function part($name, $size, $extra = '')
{
    return "--review-boundary\r\nContent-Disposition: form-data; name=\"{$name}\"; filename=\"test.txt\"\r\n" . $extra . "Content-Type: text/plain\r\n\r\n" . str_repeat('A', $size) . "\r\n";
}
foreach ([SWOOLE_BASE] as $mode) {
    $dir = sys_get_temp_dir() . '/swoole-upload-fds-' . getmypid() . '-' . $mode;
    mkdir($dir);
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $dir, $mode) {
        $cases = [];
        for ($i = 0; $i < 5; $i++) {
            $cases['duplicate_' . $i] = part('file', 80 * 1024, "Content-Disposition: form-data; name=\"second\"; filename=\"other.txt\"\r\n");
        }
        $fdCount = function () use ($pm) {
            $s = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
            fwrite($s, "GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            $out = stream_get_contents($s);
            fclose($s);
            return explode("\r\n\r\n", $out, 2)[1] ?? '';
        };
        $before = $fdCount();
        foreach ($cases as $case => $body) {
            $response = send_review_request($pm, $body . "--review-boundary--\r\n");
            $paths    = glob($dir . '/swoole.upfile.*');
            Assert::contains($response, '400 Bad Request');
            Assert::same($paths, []);
        }
        Assert::same($fdCount(), $before);
        $pm->kill();
        rmdir($dir);
    };
    $pm->childFunc = function () use ($pm, $mode, $dir) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'package_max_length' => 65536, 'upload_max_filesize' => 1024 * 1024, 'upload_tmp_dir' => $dir]);
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('request', function ($req, $res) { $res->end(json_encode(['open_fds' => count(glob('/proc/self/fd/*'))])); });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

?>
--EXPECT--
