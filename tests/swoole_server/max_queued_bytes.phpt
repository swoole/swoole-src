--TEST--
swoole_server: max_queued_bytes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 10 * 1024 * 1024;

$pm = new SwooleTest\ProcessManager;
$pm->initFreePorts();

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        echo "FAILED\n";
        $pm->kill();
        return;
    }
    $bytes = 0;
    while ($bytes < N) {
        $write_n = $client->send(random_bytes(rand(1000, 80000)));
        if ($write_n == false) {
            break;
        } else {
            $bytes += $write_n;
            phpt_echo("Client sent {$bytes} bytes\n");
        }
    }
    Assert::assert($bytes > N);
    $pm->wait();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'max_queued_bytes' => 1024 * 1024,
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', static function ($serv, $fd, $reactor_id, $data) use ($pm) {
        static $bytes;
        $bytes += strlen($data);
        phpt_echo("Server received {$bytes} bytes\n");
        usleep(1000);
        if ($bytes > N) {
            $pm->wakeup();
        }
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
DONE
