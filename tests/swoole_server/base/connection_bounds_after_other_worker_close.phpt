--TEST--
swoole_server/base: another worker closing its highest fd preserves local connections and shutdown
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (PHP_OS_FAMILY === 'Windows') {
    die('skip requires forked BASE workers');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Event;
use Swoole\Server;

function waitForStage(Atomic $stage, int $expected): void
{
    $deadline = microtime(true) + 5;
    while ($stage->get() < $expected && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::true($stage->get() >= $expected);
}

$pm = new SwooleTest\ProcessManager;
$stage = new Atomic(0);
$logFile = tempnam(sys_get_temp_dir(), 'swoole-bounds-');
$snapshot = null;
$pm->parentFunc = function () use ($pm, $stage, &$snapshot) {
    $address = 'tcp://127.0.0.1:' . $pm->getFreePort();
    $held = stream_socket_client($address, $errno, $error, 5);
    Assert::true(is_resource($held));
    stream_set_timeout($held, 5);
    $closing = null;
    try {
        fwrite($held, "hold\n");
        waitForStage($stage, 2);
        $closing = stream_socket_client($address, $errno, $error, 5);
        Assert::true(is_resource($closing));
        stream_set_timeout($closing, 5);
        fwrite($closing, "close\n");
        Assert::same(fgets($closing), "closed\n");
        $snapshot = json_decode(fgets($held), true, 512, JSON_THROW_ON_ERROR);
        $pm->kill();
        // Keep the idle socket open until the worker exits, rather than helping its reactor drain.
        Assert::same(fread($held, 1), '');
    } finally {
        $pm->kill();
        if (is_resource($closing)) {
            fclose($closing);
        }
        fclose($held);
    }
};
$pm->childFunc = function () use ($pm, $stage, $logFile) {
    $reserved = [];
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 2,
        'enable_coroutine' => false,
        'max_wait_time' => 2,
        'open_eof_check' => true,
        'package_eof' => "\n",
        'log_file' => $logFile,
    ]);
    $server->on('WorkerStart', function (Server $server, int $workerId) use ($pm, $stage, &$reserved) {
        if ($workerId === 1) {
            // This worker's accepted fd must exceed the fd held by worker zero.
            for ($i = 0; $i < 64; $i++) {
                $reserved[] = fopen('/dev/null', 'r');
            }
            $stage->set(1);
            waitForStage($stage, 2);
        } else {
            waitForStage($stage, 1);
            $pm->wakeup();
        }
    });
    $server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) use ($stage) {
        if ($server->worker_id === 1) {
            Assert::same($data, "close\n");
            $server->send($fd, "closed\n");
            $server->close($fd);
            return;
        }
        Assert::same($data, "hold\n");
        $stage->set(2);
        // Block this worker so only worker one can accept and close the second connection.
        waitForStage($stage, 3);
        $stats = $server->stats();
        $info = $server->getClientInfo($fd);
        $server->send($fd, json_encode([
            'listed' => in_array($fd, $server->getClientList(0, 100) ?: [], true),
            'iterated' => in_array($fd, iterator_to_array($server->connections, false), true),
            'stats_include_fd' => $stats['min_fd'] <= $info['socket_fd'] && $info['socket_fd'] <= $stats['max_fd'],
        ]) . "\n");
    });
    $server->on('Close', function (Server $server) use ($stage) {
        if ($server->worker_id === 1) {
            // onClose runs before close_connection updates the fd bound.
            Event::defer(function () use ($stage) {
                $stage->set(3);
            });
        }
    });
    $server->start();
};
$pm->childFirst();
try {
    $pm->run();
    $pm->expectExitCode(0);
    var_dump($snapshot['listed']);
    var_dump($snapshot['iterated']);
    var_dump($snapshot['stats_include_fd']);
    var_dump(strpos(file_get_contents($logFile), 'ERRNO 9101') === false);
} finally {
    unlink($logFile);
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
