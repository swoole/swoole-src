--TEST--
swoole_http_server_coro: add server addr
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

$output = shell_exec('ip addr show');
preg_match_all('/inet (\d+\.\d+\.\d+\.\d+)\//', $output, $matches);
$ips = $matches[1];

$pm->parentFunc = function ($pid) use ($pm, $port, $ips) {
    run(function () use ($pm, $port, $ips) {
        $client = new Client($ips[1], $port);
        $client->get('/');
        $client->close();
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm, $port, $ips) {
    run(function () use ($pm, $port, $ips) {
        $server = new Server('0.0.0.0', $port, false);
        $server->handle('/', function (Request $request, Response $response) use ($ips){
            $server = $request->server;
            Assert::eq($server['server_addr'], $ips[1]);
            Assert::eq($server['remote_addr'], $ips[1]);
            Assert::true($server['server_port'] != $server['remote_port']);
        });

        Swoole\Process::signal(SIGTERM, function () use ($server) {
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
