--TEST--
swoole_http2_client_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort(), true);
        $chan = new Channel(1);
        go(function () use ($client, $chan) {
            $client->connect();
            $req = new Request();
            $uuid = uniqid();
            $req->method = 'GET';
            $req->path = '/base64/' . base64_encode($uuid);
            $client->send($req);
            $chan->push(true);
            $resp = $client->recv();
            Assert::notNull($resp);
            Assert::eq($resp->statusCode, 200);
            Assert::eq($resp->data, $uuid);
            $chan->pop();
        });
        go(function () use ($client, $chan) {
            Assert::eq($client->connect(), false);
            $uuid = uniqid();
            $req = new Request();
            $req->method = 'GET';
            $req->path = '/base64/' . base64_encode($uuid);
            $client->send($req);
            $chan->push(true);
            Assert::eq($client->recv(), false);
            $chan->pop();
        });
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function ($request, $response) {
        $response->end(base64_decode(substr($request->server['request_uri'], 8)));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();

?>
--EXPECT--
