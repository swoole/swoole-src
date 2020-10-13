--TEST--
swoole_http2_client_coro: sock type unix
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http2\Request;
use Swoole\Http2\Response;
use Swoole\Coroutine\Http2\Client;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Client('unix:/' . UNIXSOCK_PATH, 0, false);
        Assert::eq($client->connect(), true);
        $req = new Request();
        $req->method = 'POST';
        $req->path = '/';
        $client->send($req);
        $result = $client->recv();
        Assert::eq($result->data, "OK");

        $client = new Client('unix://' . UNIXSOCK_PATH, 0, false);
        Assert::eq($client->connect(), true);
        $req = new Request();
        $req->method = 'POST';
        $req->path = '/';
        $client->send($req);
        $result = $client->recv();
        Assert::eq($result->data, "OK");

        $client = new Client('unix:///' . UNIXSOCK_PATH, 0, false);
        Assert::eq($client->connect(), true);
        $req = new Request();
        $req->method = 'POST';
        $req->path = '/';
        $client->send($req);
        $result = $client->recv();
        Assert::eq($result->data, "OK");
    });
    Swoole\Event::wait();
    @unlink(UNIXSOCK_PATH);
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Server(UNIXSOCK_PATH, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_STREAM);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true
    ]);
    $server->on("workerStart", function ($server) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (\Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
