--TEST--
swoole_http_server_coro: check if the HTTP cookie contains CRLF
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
        $client->get('/rawcookie');
        $headers = $client->getHeaders();
        Assert::false(isset($headers['malicious-header']));
        Assert::false(isset($headers['set-cookie']));

        $client->get('/cookie');
        $headers = $client->getHeaders();
        Assert::false(isset($headers['malicious-header']));
        Assert::true(isset($headers['set-cookie']));

        $client->close();
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort());

        $server->handle('/rawcookie', function (Request $request, Response $response) {
            $value = "cn\r\nmalicious-header:injected\r\nContent-Length:27\r\n\r\n<h3>malicious response body";
            $response->rawcookie('lang', $value);
            $response->end('hello world');
        });

        $server->handle('/cookie', function (Request $request, Response $response) {
            $value = "cn\r\nmalicious-header:injected\r\nContent-Length:27\r\n\r\n<h3>malicious response body";
            $response->cookie('lang', $value);
            $response->end('hello world');
        });

        $server->start();
    });
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::rawcookie(): Header may not contain more than a single header, new line detected in %s
DONE
