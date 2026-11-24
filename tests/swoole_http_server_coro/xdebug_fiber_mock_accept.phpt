--TEST--
swoole_http_server_coro: Xdebug observes Fiber switches from internal coroutine entries
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('xdebug');
skip('requires Xdebug 3.5 or later', version_compare(phpversion('xdebug'), '3.5', '<'));
?>
--ENV--
XDEBUG_MODE=debug
--INI--
swoole.enable_fiber_mock=On
xdebug.start_with_request=yes
xdebug.client_host=127.0.0.1
xdebug.client_port=9
xdebug.connect_timeout_ms=200
xdebug.log_level=0
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

if (!in_array('debug', xdebug_info('mode'), true)) {
    throw new RuntimeException('Xdebug step debugging is inactive');
}

class RequestHandler
{
    public function handle(Response $response): void
    {
        Coroutine::create(function () use ($response) {
            Coroutine::sleep(0.005);
            $response->end('ok');
        });
    }
}

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $handler = new RequestHandler();
    $server->handle('/', function (Request $request, Response $response) use ($handler) {
        $handler->handle($response);
    });
    Coroutine::create(fn () => $server->start());

    $client = new Client('127.0.0.1', $server->port);
    $client->set(['timeout' => 2]);
    try {
        var_dump($client->get('/'));
        var_dump($client->getStatusCode(), $client->getBody());
    } finally {
        $client->close();
        $server->shutdown();
    }
});
?>
--EXPECT--
bool(true)
int(200)
string(2) "ok"
