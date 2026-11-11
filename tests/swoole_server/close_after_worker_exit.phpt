--TEST--
swoole_server: the reactor reclaims a connection when its worker is killed during onClose without heartbeat
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

$closes = new Atomic();
$retired = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(15);
$pm->parentFunc = function () use ($pm, $closes, $retired) {
    $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 10);
    stream_set_timeout($client, 10);
    fwrite($client, 'begin');
    Assert::same(fgets($client), "ready\n");
    // Send EOF while keeping the peer open across transport shutdown and fd retirement.
    Assert::true(stream_socket_shutdown($client, STREAM_SHUT_WR));
    Assert::same(stream_get_contents($client), '');
    Assert::false(stream_get_meta_data($client)['timed_out']);
    // EOF alone only proves shutdown(). The replacement worker observes physical retirement.
    $deadline = microtime(true) + 10;
    while ($retired->get() === 0 && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($retired->get(), 1);
    Assert::same($closes->get(), 1);
    fclose($client);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $closes, $retired) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'enable_coroutine' => false,
        'heartbeat_check_interval' => 0,
        // Connection reclamation must not wait for this reload/shutdown timeout.
        'max_wait_time' => 30,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server) use ($pm, $retired) {
        Swoole\Timer::tick(10, function () use ($server, $retired) {
            $retired->set($server->stats()['close_count']);
        });
        $pm->wakeup();
    });
    $server->on('receive', function (Server $server, int $fd) {
        Assert::true($server->send($fd, "ready\n"));
    });
    $server->on('workerExit', function () {
        Swoole\Timer::clearAll();
    });
    $server->on('close', function () use ($closes) {
        Assert::same($closes->add(), 1);
        // Bypass exception handling so the worker cannot acknowledge CLOSE.
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
