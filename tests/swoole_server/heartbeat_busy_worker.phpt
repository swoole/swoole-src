--TEST--
swoole_server: heartbeat shuts down transport I/O and retains the session for a busy worker's onClose
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

$busy           = new Atomic();
$release        = new Atomic();
$closes         = new Atomic();
$pm             = new ProcessManager();
$pm->setWaitTimeout(15);
$pm->parentFunc = function () use ($pm, $busy, $release, $closes) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 10);
    stream_set_timeout($client, 15);
    fwrite($client, 'block');
    Assert::same(fgets($client), "ready\n");
    Assert::same(stream_get_contents($client), '');
    Assert::false(stream_get_meta_data($client)['timed_out']);
    Assert::same($busy->get(), 1);
    Assert::same($closes->get(), 0);
    // Stay alive and busy beyond the former max_wait_time + 2 * heartbeat deadline.
    usleep(3300000);
    Assert::same($busy->get(), 1);
    Assert::same($closes->get(), 0);
    $release->set(1);
    $deadline = microtime(true) + 10;
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
$pm->childFunc = function () use ($pm, $busy, $release, $closes) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num'               => 1,
        'reactor_num'              => 1,
        'enable_coroutine'         => false,
        'heartbeat_idle_time'      => 1,
        'heartbeat_check_interval' => 1,
        'max_wait_time'            => 1,
        'log_file'                 => '/dev/null',
    ]);
    $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
    $server->on('receive', function (Server $server, int $fd) use ($busy, $release) {
        $busy->set(1);
        Assert::true($server->send($fd, "ready\n"));
        // Include heartbeat detection, the parent observation window and slow CI scheduling.
        $deadline = microtime(true) + 30;
        while ($release->get() === 0 && microtime(true) < $deadline) {
            usleep(10000);
        }
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
