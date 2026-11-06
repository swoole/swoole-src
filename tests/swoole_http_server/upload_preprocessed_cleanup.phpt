--TEST--
swoole_http_server: reclaim all preprocessed files after metadata rejection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
function await_upload_cleanup(string $dir): void
{
    $deadline = microtime(true) + 2;
    while (glob($dir . '/swoole.upfile.*') && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same(glob($dir . '/swoole.upfile.*'), []);
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $dir = sys_get_temp_dir() . '/swoole-upload-cleanup-' . getmypid() . '-' . $mode;
    mkdir($dir);
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $dir, $mode) {
        $cases = [
            'normal'                => part('file', 80 * 1024),
            'long_name'             => part(str_repeat('x', 600), 80 * 1024) . part('last', 1024),
            'max_input_vars'        => "--review-boundary\r\nContent-Disposition: form-data; name=\"padding\"\r\n" . str_repeat("X-Padding: ignored\r\n", 1005) . "\r\nvalue\r\n" . part('file', 80 * 1024),
            'duplicate_disposition' => part('file', 80 * 1024, "Content-Disposition: form-data; name=\"second\"; filename=\"other.txt\"\r\n"),
        ];
        foreach ($cases as $case => $body) {
            $response = send_review_request($pm, $body . "--review-boundary--\r\n");
            Assert::contains($response, $case === 'normal' ? '200 OK' : '400 Bad Request');
            await_upload_cleanup($dir);
        }
        // Disconnect while one file is complete and a later file is still being written.
        $first  = part('first', 80 * 1024);
        $body   = $first . part('last', 80 * 1024) . "--review-boundary--\r\n";
        $head   = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=review-boundary\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
        $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
        $prefix = $head . substr($body, 0, strlen($first) + 1024);
        for ($offset = 0; $offset < strlen($prefix);) {
            $written = fwrite($socket, substr($prefix, $offset));
            Assert::greaterThan($written, 0);
            $offset += $written;
        }
        $deadline = microtime(true) + 2;
        while (count(glob($dir . '/swoole.upfile.*')) < 2 && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::count(glob($dir . '/swoole.upfile.*'), 2);
        fclose($socket);
        await_upload_cleanup($dir);
        $pm->kill();
        Assert::true(rmdir($dir));
    };
    $pm->childFunc = function () use ($pm, $mode, $dir) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'package_max_length' => 65536, 'upload_max_filesize' => 1024 * 1024, 'upload_tmp_dir' => $dir]);
        set_error_handler(function ($level, $message) { return str_contains($message, 'Input variables exceeded'); });
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('request', function ($req, $res) { $res->end(json_encode($req->files)); });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

?>
--EXPECT--
