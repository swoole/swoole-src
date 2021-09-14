--TEST--
swoole_server: slow worker
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;

$data_chunks = [];

$counter_server = new Swoole\Atomic(0);
$counter_client = new Swoole\Atomic(0);

for ($i = 0; $i < MAX_REQUESTS; $i++) {
    $rand = rand(8 * 1024, 1024 * 1024);
    $data = pack('N', $rand) . str_repeat('A', $rand);
    $data_chunks[] = $data;
    $counter_client->add(strlen($data));
}

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm, $counter_server, $counter_client, $data_chunks) {
    $cli = new Client(SWOOLE_SOCK_TCP);
    $r = $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 5);
    Assert::assert($r);
    Assert::eq($cli->recv(), 'CONNECT OK'.PHP_EOL);

    foreach ($data_chunks as $chunk) {
        $cli->send($chunk);
    }

    $cli2 = new Client(SWOOLE_SOCK_TCP);
    $r = $cli2->connect(TCP_SERVER_HOST, $pm->getFreePort(), 5);
    Assert::assert($r);
    Assert::eq($cli2->recv(), 'CONNECT OK'.PHP_EOL);

    echo $cli->recv();
    Assert::eq($counter_server->get(), $counter_client->get());
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $counter_server, $counter_client) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 16 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ));

    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
        usleep(100000);
    });

    $serv->on(Swoole\Constant::EVENT_CONNECT, function (Server $serv, $fd, $rid) {
        $serv->send($fd, 'CONNECT OK'.PHP_EOL);
    });

    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($counter_server, $counter_client) {
        $counter_server->add(strlen($data));
        if ($counter_server->get() == $counter_client->get()) {
            $serv->send($fd, "DONE\n");
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
