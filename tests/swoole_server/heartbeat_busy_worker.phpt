--TEST--
swoole_server: heartbeat ends transport I/O while a busy worker still owes one onClose
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

$busy = new Atomic();
$closes = new Atomic();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $busy, $closes) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 5);
    stream_set_timeout($client, 10);
    fwrite($client, 'block');
    Assert::same(fgets($client), "ready\n");
    Assert::same(stream_get_contents($client), '');
    Assert::false(stream_get_meta_data($client)['timed_out']);
    Assert::same($busy->get(), 1);
    Assert::same($closes->get(), 0);
    $deadline = microtime(true) + 8;
    while ($closes->get() === 0 && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($closes->get(), 1);
    // A subsequent heartbeat/late CLOSE command must not dispatch the callback again.
    usleep(1100000);
    Assert::same($closes->get(), 1);
    fclose($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $busy, $closes) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'enable_coroutine' => false,
        'heartbeat_idle_time' => 1,
        'heartbeat_check_interval' => 1,
        'max_wait_time' => 6,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('receive', function (Server $server, int $fd) use ($busy) {
        $busy->set(1);
        Assert::true($server->send($fd, "ready\n"));
        usleep(5000000);
        $busy->set(0);
    });
    $server->on('close', function (Server $server, int $fd) use ($closes) {
        Assert::isArray($server->getClientInfo($fd));
        Assert::same($closes->add(), 1);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
