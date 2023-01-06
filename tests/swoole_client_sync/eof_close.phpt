--TEST--
swoole_client_sync: eof protocol [sync]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Client;

const EOF = "\r\n\r\n";
$pkg = random_bytes(rand(128 * 1024, 256 * 1024));
$pm = new ProcessManager;
$port = get_one_free_port();
$pm->parentFunc = function ($pid) use ($port, $pkg, $pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set(['open_eof_check' => true, "package_eof" => EOF]);
    if (!$client->connect('127.0.0.1', $port, 5, 0)) {
        echo "Over flow. errno=" . $client->errCode;
        die("\n");
    }

    $client->send("recv\r\n\r\n");
    $recvPkg = $client->recv();
    Assert::assert($recvPkg != false);
    $_pkg = unserialize($recvPkg);
    Assert::assert(is_array($_pkg));
    Assert::eq($_pkg['data'], $pkg);
    $recvPkg = $client->recv();
    Assert::same($recvPkg, '');
    echo "SUCCESS\n";
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port, $pkg) {
    $serv = new Server('127.0.0.1', $port, SWOOLE_BASE);
    $serv->set(array(
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'package_max_length' => 1024 * 1024 * 2,
        'socket_buffer_size' => 256 * 1024 * 1024,
        'log_file' => TEST_LOG_FILE,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($pkg) {
        $serv->send($fd, serialize(['data' => $pkg]) . EOF);
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
