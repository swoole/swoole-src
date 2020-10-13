--TEST--
swoole_client_sync: recv witch open_eof_check and check errCode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new \Swoole\Client(SWOOLE_SOCK_TCP);

    $client->set([
        'open_eof_check'     => true,
        'package_eof'        => "\n",
        'package_max_length' => 1024 * 1024 * 2,
    ]);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        throw new Exception("connect failed");
    }

    $data = @$client->recv(1024 * 1024 * 2);
    Assert::false($data);
    Assert::eq(11, $client->errCode);
    $client->close();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $serv = new Server("127.0.0.1", $pm->getFreePort());

    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);

    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
    });

    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
