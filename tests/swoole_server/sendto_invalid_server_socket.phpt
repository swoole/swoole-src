--TEST--
swoole_server: invalid server_socket for send and sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

$udpPort = get_one_free_port();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $udpPort) {
    $client = new Client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC);
    Assert::true($client->connect('127.0.0.1', $udpPort));
    Assert::greaterThan($client->send('ping'), 0);
    Assert::same($client->recv(), "udp-ok\n");
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $udpPort) {
    $serv = new Server('127.0.0.1', $udpPort, SWOOLE_BASE, SWOOLE_SOCK_UDP);
    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('packet', function (Server $serv, string $data, array $client) {
        Assert::false($serv->sendto($client['address'], $client['port'], 'bad', PHP_INT_MAX));
        Assert::true($serv->sendto($client['address'], $client['port'], "udp-ok\n"));
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();

$socketFile = __DIR__ . '/send_invalid_server_socket.sock';
@unlink($socketFile);
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $socketFile) {
    $client = new Client(SWOOLE_SOCK_UNIX_DGRAM, SWOOLE_SOCK_SYNC);
    Assert::true($client->connect($socketFile, 0, -1));
    Assert::greaterThan($client->send('ping'), 0);
    Assert::same($client->recv(), "unix-ok\n");
    $client->close();
    @unlink($socketFile);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $socketFile) {
    $serv = new Server($socketFile, 0, SWOOLE_BASE, SWOOLE_SOCK_UNIX_DGRAM);
    $serv->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('packet', function (Server $serv, string $data, array $client) {
        Assert::false($serv->send($client['address'], 'bad', PHP_INT_MAX));
        Assert::true($serv->send($client['address'], "unix-ok\n"));
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();

echo "DONE\n";
?>
--EXPECT--
DONE
