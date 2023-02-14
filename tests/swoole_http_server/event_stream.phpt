--TEST--
swoole_http_server: event stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const N = 128;
$pm = new ProcessManager;

$data = [];
for ($i = N; $i--;) {
    $data[] = 'data: ' . base64_encode(random_bytes(random_int(16, 128))) . "\n\n";
}

$pm->parentFunc = function () use ($pm, $data) {
    Co\run(function () use ($pm, $data) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/'));
        Assert::isEmpty($client->getBody());
        Assert::keyNotExists($client->headers, 'content-length');
        Assert::eq($client->headers['content-type'], "text/event-stream");
        for ($i = 0; $i < N; $i++) {
            Co::sleep(0.01);
            $line1 = $client->socket->recvLine();
            $line2 = $client->socket->recvLine();
            Assert::eq($line1 . $line2, $data[$i]);
        }
        $pm->kill();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $data) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->on('WorkerStart', function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function ($req, Swoole\Http\Response $resp) use ($http, $data) {
        $resp->header("Content-Type", "text/event-stream");
        $resp->header("Cache-Control", "no-cache");
        $resp->header("Connection", "keep-alive");
        $resp->header("X-Accel-Buffering", "no");
        $resp->header('Content-Encoding', '');
        $resp->header("Content-Length", '');
        $resp->end();
        Co::sleep(0.05);
        for ($i = 0; $i < N; $i++) {
            Co::sleep(0.01);
            $http->send($resp->fd, $data[$i]);
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
