--TEST--
swoole_server: every reactor reclaims waiting sessions after the same worker exits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

const CONNECTIONS = 4;
$allowExit = new Atomic();
$retired = new Atomic();
$starts = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(15);
$pm->parentFunc = function () use ($pm, $allowExit, $retired) {
    $clients = [];
    $reactors = [];
    for ($i = 0; $i < CONNECTIONS; $i++) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 10);
        stream_set_timeout($client, 10);
        fwrite($client, 'begin');
        $reactors[(int) fgets($client)] = true;
        $clients[] = $client;
    }
    Assert::same(count($reactors), 2);
    foreach ($clients as $client) {
        Assert::true(stream_socket_shutdown($client, STREAM_SHUT_WR));
        Assert::same(stream_get_contents($client), '');
        Assert::false(stream_get_meta_data($client)['timed_out']);
    }
    $allowExit->set(1);
    $deadline = microtime(true) + 10;
    while ($retired->get() < CONNECTIONS && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($retired->get(), CONNECTIONS);
    foreach ($clients as $client) {
        fclose($client);
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $allowExit, $retired, $starts) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 2,
        'reactor_num' => 2,
        'enable_coroutine' => false,
        'heartbeat_check_interval' => 0,
        'max_wait_time' => 30,
        // One worker receives all clients, while fd ownership spans both reactor threads.
        'dispatch_mode' => SWOOLE_DISPATCH_IPMOD,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server) use ($pm, $retired, $starts) {
        Swoole\Timer::tick(10, function () use ($server, $retired) {
            $retired->set($server->stats()['close_count']);
        });
        if ($starts->add() === 2) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Server $server, int $fd, int $reactorId) {
        Assert::true($server->send($fd, $reactorId . "\n"));
    });
    $server->on('workerExit', function () {
        Swoole\Timer::clearAll();
    });
    $server->on('close', function () use ($allowExit) {
        // This watchdog must outlast parent-side I/O and scheduling delays.
        $deadline = microtime(true) + 30;
        while ($allowExit->get() === 0 && microtime(true) < $deadline) {
            usleep(10000);
        }
        Swoole\Process::kill(getmypid(), SIGKILL);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
