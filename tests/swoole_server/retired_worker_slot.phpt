--TEST--
swoole_server: a draining worker cannot reset its replacement's counters on another SIGTERM
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('posix_kill');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Timer;

function waitFlag(Atomic $flag, int $expected): void
{
    $deadline = microtime(true) + 3;
    while ($flag->get() !== $expected) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Worker handoff did not complete');
        }
        Coroutine::sleep(0.005);
    }
}

$generation = new Atomic();
$oldPid = new Atomic();
$newRequestCompleted = new Atomic();
$releaseOld = new Atomic();
$oldStopped = new Atomic();
$pm = new SwooleTest\ProcessManager();
$pm->setWaitTimeout(10);
$pm->parentFunc = function () use ($pm, $generation, $newRequestCompleted, $releaseOld, $oldStopped) {
    Coroutine\run(function () use ($pm, $generation, $newRequestCompleted, $releaseOld, $oldStopped) {
        $old = new Client(SWOOLE_SOCK_TCP);
        $old->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($old->connect('127.0.0.1', $pm->getFreePort(), 3));
        Assert::same($old->send("old\n"), 4);
        waitFlag($generation, 2);

        $replacement = new Client(SWOOLE_SOCK_TCP);
        $replacement->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($replacement->connect('127.0.0.1', $pm->getFreePort(), 3));
        Assert::same($replacement->send("new\n"), 4);
        Assert::same($replacement->recv(), "new\n");
        // A timer on the replacement runs after its first native receive callback has returned.
        waitFlag($newRequestCompleted, 1);
        $releaseOld->set(1);
        Assert::same($old->recv(), "old\n");
        waitFlag($oldStopped, 1);

        Assert::same($replacement->send("stats\n"), 6);
        $stats = json_decode($replacement->recv(), true, flags: JSON_THROW_ON_ERROR);
        Assert::same($stats['requests'], 1);
        Assert::same($stats['responses'], 1);
        $replacement->close();
        $old->close();
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $generation, $oldPid, $newRequestCompleted, $releaseOld, $oldStopped) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reload_async' => true,
        'max_wait_time' => 3,
        'dispatch_mode' => SWOOLE_DISPATCH_CO_CONN_LB,
        'open_eof_check' => true,
        'package_eof' => "\n",
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm, $generation, $oldPid) {
        if ($generation->add() === 1) {
            $oldPid->set(getmypid());
            $pm->wakeup();
        }
    });
    $server->on('WorkerStop', function () use ($oldPid, $oldStopped) {
        if (getmypid() === $oldPid->get()) {
            $oldStopped->set(1);
        }
    });
    $server->on('Receive', function ($server, $fd, $reactorId, $data) use ($newRequestCompleted, $releaseOld) {
        if ($data === "old\n") {
            Assert::true($server->stop());
            waitFlag($releaseOld, 1);
            Assert::true(posix_kill(getmypid(), SIGTERM));
            Coroutine::sleep(0.02);
            // Completing this old response must not increment the replacement's response counter.
            Assert::true($server->send($fd, "old\n"));
        } elseif ($data === "new\n") {
            Assert::true($server->send($fd, "new\n"));
            Timer::after(1, function () use ($newRequestCompleted) { $newRequestCompleted->set(1); });
        } else {
            $stats = $server->stats();
            Assert::true($server->send($fd, json_encode([
                'requests' => $stats['worker_request_count'],
                'responses' => $stats['worker_response_count'],
            ], JSON_THROW_ON_ERROR) . "\n"));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
