--TEST--
swoole_client_sync: bind address
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set([
        'bind_address' => '127.0.0.1',
        'bind_port' => $pm->getFreePort(),
    ]);

    Assert::false($client->connect('127.0.0.1', 9501));
    Assert::eq($client->errCode, SOCKET_EADDRINUSE);
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Client::connect(): bind address or port error in set method in %s
DONE
