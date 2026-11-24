--TEST--
swoole_http2_client_coro: http2 without gzip and recv big data (window-update)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
$body = str_repeat('HTTP/2 without gzip ', 32768);
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $body) {
    try {
        Co\run(function () use ($pm, $body) {
            $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort(), true);
            $cli->set(['timeout' => 5, 'ssl_host_name' => 'localhost', 'ssl_verify_peer' => false]);
            Assert::true($cli->connect());
            $req = new Swoole\Http2\Request;
            $req->path = '/large';
            $req->headers = ['host' => 'localhost', 'accept-encoding' => ''];
            $sent = $received = [];
            for ($i = 0; $i < 5; $i++) {
                $id = $cli->send($req);
                Assert::greaterThan($id, 0);
                $sent[] = $id;
            }
            for ($i = 0; $i < 5; $i++) {
                $response = $cli->recv();
                Assert::isInstanceOf($response, Swoole\Http2\Response::class);
                Assert::same($response->statusCode, 200);
                Assert::same($response->data, $body);
                Assert::false(isset($response->headers['content-encoding']));
                $received[] = $response->streamId;
            }
            sort($received);
            Assert::same($received, $sent);
            $cli->close();
        });
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm, $body) {
    $server = new Swoole\Http\Server(
        '127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL
    );
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'http_compression' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) use ($body) {
        $response->header('Content-Type', 'text/plain');
        $response->end($body);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
