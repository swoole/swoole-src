--TEST--
swoole_http2_server: parse multipart headers with shared completion callbacks
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_http2();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$boundary = 'swoole-http2-boundary';
$body = "--{$boundary}\r\n";
$body .= "Content-Disposition: form-data; name=\"field\"\r\n\r\n";
$body .= "field-value\r\n";
$body .= "--{$boundary}\r\n";
$body .= "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n";
$body .= "Content-Type: text/plain\r\n\r\n";
$body .= "file-value\r\n";
$body .= "--{$boundary}--\r\n";

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $boundary, $body) {
    Co\run(function () use ($pm, $boundary, $body) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());
        $request = new Swoole\Http2\Request;
        $request->method = 'POST';
        $request->headers = ['content-type' => "multipart/form-data; boundary={$boundary}"];
        $request->data = $body;
        Assert::greaterThan($client->send($request), 0);
        $response = $client->recv();
        Assert::same($response->statusCode, 200);
        Assert::same($response->data, 'OK');
        $client->close();
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::same($request->post['field'], 'field-value');
        Assert::same($request->files['file']['name'], 'test.txt');
        Assert::same($request->files['file']['type'], 'text/plain');
        Assert::same(file_get_contents($request->files['file']['tmp_name']), 'file-value');
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
