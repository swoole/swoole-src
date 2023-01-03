--TEST--
swoole_server: slow master
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Constant;
use Swoole\Server;
use Swoole\Timer;

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
    $cli->send('hello world');

    usleep(10000);

    $n = $counter_client->get();
    $data = '';
    while (strlen($data) < $n) {
        $_recv = $cli->recv();
        if (empty($_recv)) {
            break;
        }
        $data .= $_recv;
    }
    Assert::eq($data, implode('', $data_chunks));
    $cli->close();
    $pm->kill();
    Assert::greaterThanEq($counter_server->get(), 5);
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $counter_server, $counter_client, $data_chunks) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'single_thread' => true,
    ));

    $serv->on(Constant::EVENT_START, function () use ($pm)  {
        $pm->wakeup();
        Timer::after(50, function (){
            usleep(300000);
        });
    });

    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($counter_server, $counter_client, $data_chunks) {
        $serv->timer = Timer::tick(50, function () use ($counter_server) {
            $counter_server->add(1);
        });
        foreach ($data_chunks as $chunk) {
            $serv->send($fd, $chunk);
        }
    });

    $serv->on(Constant::EVENT_CLOSE, function ($serv) use ($pm)  {
        Timer::clear($serv->timer);
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
