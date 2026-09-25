--TEST--
swoole_http_server: retain uploaded file until request shutdown
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class RequestHolder
{
    public static ?Swoole\Http\Request $request = null;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $boundary = '------------------------d3f990cdce762596';
    $body = implode("\r\n", [
        '--' . $boundary,
        'Content-Disposition: form-data; name="file"; filename="test.jpg"',
        'Content-Type: image/jpeg',
        '',
        file_get_contents(TEST_IMAGE),
        '--' . $boundary . '--',
        '',
    ]);
    $request = implode("\r\n", [
        'POST / HTTP/1.1',
        'Host: 127.0.0.1',
        'Connection: close',
        'Content-Type: multipart/form-data; boundary=' . $boundary,
        'Content-Length: ' . strlen($body),
        '',
        $body,
    ]);

    $socket = stream_socket_client("tcp://127.0.0.1:{$pm->getFreePort()}");
    fwrite($socket, $request);
    $response = stream_get_contents($socket);
    fclose($socket);
    $parts = explode("\r\n\r\n", $response, 2);
    Assert::count($parts, 2);
    Assert::same($parts[1], md5_file(TEST_IMAGE));

    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'worker_num' => 1,
        'package_max_length' => 64 * 1024,
        'upload_max_filesize' => 8 * 1024 * 1024,
    ]);
    $http->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $tmpName = $request->files['file']['tmp_name'];
        Assert::true(is_file($tmpName));
        Assert::same(md5_file($tmpName), md5_file(TEST_IMAGE));
        RequestHolder::$request = $request;
        $response->end(md5_file($tmpName));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
?>
--EXPECT--
