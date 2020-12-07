--TEST--
swoole_http_server_coro: check if the HTTP header contains CRLF
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->get('/?r=AAA%0d%0amalicious-header:injected');
        $headers = $client->getHeaders();
        Assert::false(isset($headers['malicious-header']));
        $client->close();
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());

        $server->handle('/', function (Request $request, Response $response) {
            $response->header('Location', $request->get['r']);
            $response->status(302);
            $response->end('Redirecting...');
        });

        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::end(): Header may not contain more than a single header, new line detected in %s
DONE
