--TEST--
swoole_http_server: reject uploads whose final stdio flush fails
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (!function_exists('posix_setrlimit') || !defined('POSIX_RLIMIT_FSIZE') || !function_exists('pcntl_signal')) {
    exit('skip requires POSIX file size limits and pcntl');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm  = new ProcessManager();
$dir = sys_get_temp_dir() . '/swoole-upload-flush-' . getmypid();
mkdir($dir);
$pm->parentFunc = function () use ($pm, $dir) {
    // Small uploads use the PHP parser rather than the large-body preprocessor.
    $small = "--review\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\n"
        . str_repeat('A', 2048) . "\r\n--review--\r\n";
    $head   = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=review\r\nContent-Length: " . strlen($small) . "\r\n\r\n";
    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $errno, $error, 2);
    stream_set_timeout($socket, 2);
    Assert::same(fwrite($socket, $head . $small), strlen($head . $small));
    $response = stream_get_contents($socket);
    fclose($socket);
    Assert::contains($response, '200 OK');
    $files = json_decode(explode("\r\n\r\n", $response, 2)[1], true);
    Assert::same($files['file']['error'], UPLOAD_ERR_CANT_WRITE);
    Assert::same($files['file']['size'], 1024);

    $body = '';
    for ($i = 0; $i < 40; $i++) {
        $body .= "--review\r\nContent-Disposition: form-data; name=\"file{$i}\"; filename=\"test.txt\"\r\n\r\n" . str_repeat('A', 2048) . "\r\n";
    }
    $body .= "--review--\r\n";
    $headers = "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary=review\r\nContent-Length: " . strlen($body) . "\r\n\r\n";
    $s       = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}", $e, $m, 2);
    stream_set_timeout($s, 2);
    fwrite($s, $headers . $body);
    $out = stream_get_contents($s);
    fclose($s);
    Assert::contains($out, '503 Service Unavailable');
    Assert::same(glob($dir . '/swoole.upfile.*'), []);
    $pm->kill();
    foreach (glob($dir . '/*') as $path) {
        unlink($path);
    }
    rmdir($dir);
};
$pm->childFunc = function () use ($pm, $dir) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'package_max_length' => 65536, 'upload_max_filesize' => 1024 * 1024, 'upload_tmp_dir' => $dir]);
    $server->on('workerStart', function () use ($pm) {
        pcntl_signal(SIGXFSZ, SIG_IGN);
        posix_setrlimit(POSIX_RLIMIT_FSIZE, 1024, 1024);
        $pm->wakeup();
    });
    $server->on('request', function ($req, $res) {
        $sizes = array_map(function ($f) {return ['error' => $f['error'], 'size' => $f['size']]; }, $req->files ?? []);
        $res->end(json_encode($sizes));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
