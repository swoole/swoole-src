--TEST--
swoole_http_server_coro: parse fragmented multipart headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$boundary = 'swoole-fragmented-boundary';
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
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $headers = "POST / HTTP/1.1\r\nHost: localhost\r\n";
        $headers .= "Content-Type: multipart/form-data; boundary={$boundary}\r\n";
        $headers .= "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        Assert::same($client->send($headers), strlen($headers));
        foreach (str_split($body) as $byte) {
            Assert::same($client->send("1\r\n{$byte}\r\n"), 6);
        }
        Assert::same($client->send("0\r\n\r\n"), 5);
        Assert::contains($client->recv(), 'OK');
        $client->close();
    });
};
$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server) {
            Assert::same($request->post['field'], 'field-value');
            Assert::same($request->files['file']['name'], 'test.txt');
            Assert::same($request->files['file']['type'], 'text/plain');
            Assert::same(file_get_contents($request->files['file']['tmp_name']), 'file-value');
            $response->end('OK');
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
