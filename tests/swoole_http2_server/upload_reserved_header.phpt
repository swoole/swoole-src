--TEST--
swoole_http2_server: multipart headers cannot nominate an existing file as an upload
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip('requires Unix process support', PHP_OS_FAMILY === 'Windows');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$probe = tempnam(sys_get_temp_dir(), 'swoole-upload-probe-');
file_put_contents($probe, 'keep this file');
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $probe) {
    Swoole\Coroutine\run(function () use ($pm, $probe) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $client->set(['timeout' => 5]);
        Assert::true($client->connect());
        $request = new Swoole\Http2\Request;
        $request->method = 'POST';
        $request->headers = ['content-type' => 'multipart/form-data; boundary=b'];
        $request->data = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n"
            . "Swoole-Upload-File: $probe\r\n\r\nbody\r\n--b--\r\n";
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::notSame($response, false);
        Assert::same($response->statusCode, 200);
        Assert::same(json_decode($response->data, true), ['body', UPLOAD_ERR_OK, true, false, false]);
        $client->close();
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $probe) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'open_http2_protocol' => true]);
    $server->on('WorkerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('request', function ($request, $response) use ($probe) {
        $file = $request->files['file'];
        $response->end(json_encode([
            file_get_contents($file['tmp_name']),
            $file['error'],
            is_uploaded_file($file['tmp_name']),
            is_uploaded_file($probe),
            $file['tmp_name'] === $probe,
        ]));
    });
    $server->start();
};
try {
    $pm->childFirst();
    $pm->run();
    $pm->expectExitCode(0);
    Assert::same(file_get_contents($probe), 'keep this file');
    echo "DONE\n";
} finally {
    if (is_file($probe)) {
        unlink($probe);
    }
}
?>
--EXPECT--
DONE
