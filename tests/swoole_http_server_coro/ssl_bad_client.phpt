--TEST--
swoole_http_server_coro: bad client
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Co\Client;
use Co\Http\Server;
use Swoole\Event;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $port = $pm->getFreePort();
        $client = new Client(SWOOLE_SOCK_TCP); // 同步阻塞
        if (!$client->connect('127.0.0.1', $port)) {
            exit("connect failed\n");
        }
        $client->send('hello world');
        while (true) {
            $data = $client->recv();
            if (!$data) {
                break;
            }
        }
        echo httpGetBody("https://127.0.0.1:{$port}/stop?hello=1") . PHP_EOL;
    });
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), true);
        $server->set([
            'open_tcp_nodelay' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        ]);
        $server->handle('/', function ($request, $response) {
            $response->end('<h1>Index</h1>');
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end('<h1>Stop</h1>');
            $server->shutdown();
        });
        $server->start();
    });
    Event::wait();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	WARNING	Socket::ssl_accept(): bad SSL client[127.0.0.1:%d], reason=%d, error_string=%s
<h1>Stop</h1>
