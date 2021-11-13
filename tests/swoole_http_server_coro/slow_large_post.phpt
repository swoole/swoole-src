--TEST--
swoole_http_server_coro: slow large post
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

const N1 = 2048;
const N2 = 8192;
const KEY = 'test_key';
define('VALUE', random_bytes(N1 + N2));

$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->connect("127.0.0.1", $pm->getFreePort());
    $post_data = KEY . '=' . urlencode(VALUE);
    $len = strlen($post_data);
    $data = "POST /index.html HTTP/1.1\r\nServer: nginx\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\nContent-Length: $len\r\nX-Server: swoole\r\n\r\n$post_data";

    $client->send(substr($data, 0, N1));
    usleep(30000);
    $client->send(substr($data, N1, N2));
    usleep(30000);
    $client->send(substr($data, N1 + N2));

    $data = $client->recv();
    Assert::stringNotEmpty($data);
    Assert::true(swoole_string($data)->contains('HTTP/1.1 200 OK'));
    $pm->kill();
    echo "OK\n";
};

$pm->childFunc = function () use ($pm)
{
    run(function () use($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());
        $server->handle('/', function (Request $request, Response $response) use ($pm) {
            Assert::same($request->header['server'], 'nginx');
            Assert::same($request->header['x-server'], 'swoole');
            Assert::same($request->header['content-type'], 'application/x-www-form-urlencoded');
            Assert::eq($request->header['content-length'], strlen($request->getContent()));
            Assert::eq(VALUE, $request->post[KEY]);
            $response->end("OK");
        });
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
