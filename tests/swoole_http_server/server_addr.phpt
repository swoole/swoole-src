--TEST--
swoole_http_server: add server addr
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$output = shell_exec('ip addr show');
preg_match_all('/inet (\d+\.\d+\.\d+\.\d+)\//', $output, $matches);
$ips = $matches[1];

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm, $ips) {
    Co\run(function () use ($pm, $ips) {
        $body = httpGetBody("http://{$ips[1]}:{$pm->getFreePort()}");
        Assert::eq($body, 'Hello World');
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $ips) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm, $ips) {
        $server = $request->server;
        Assert::eq($server['server_addr'], $ips[1]);
        Assert::eq($server['remote_addr'], $ips[1]);
        Assert::true($server['server_port'] != $server['remote_port']);
        $response->status(200, "status");
        $response->end("Hello World");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
DONE
