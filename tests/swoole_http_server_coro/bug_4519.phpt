--TEST--
swoole_http_server_coro: bug #4519
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$pm = new ProcessManager;
$pm->initFreePorts();

$port = $pm->getFreePort();
$data = str_repeat('你好你好你好', 10000);
$length = strlen($data);

$pm->parentFunc = function ($pid) use ($pm, $data, $port) {
    run(function () use ($pm, $data, $port) {
        $client = new Client('127.0.0.1', $port);
        $client->setHeaders([
            'Content-type' => 'application/x-www-form-urlencoded',
        ]);
        $client->post('/api', ['test' => $data]);
        $client->close();
        $pm->kill();
        echo "DONE";
    });
};

$pm->childFunc = function () use ($pm, $length, $port) {
    run(function () use ($pm, $length, $port) {
        $server = new Server('127.0.0.1', $port, false);
        $server->handle('/api', function ($request, $response) use ($length){
            Assert::assert(sizeof($request->post) == 1 && strlen($request->post['test']) == $length);
        });

        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
