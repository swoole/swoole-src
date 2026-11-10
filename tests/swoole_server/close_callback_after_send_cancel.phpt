--TEST--
swoole_server: onClose still runs once when a cancelled sender reset-closes the session
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Client;
use Swoole\Coroutine;
use Swoole\Server;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $closes = new Atomic();
    $cancelled = new Atomic();
    $pm = new ProcessManager();
    $pm->setWaitTimeout(10);
    $pm->parentFunc = function () use ($pm, $closes, $cancelled) {
        $client = new Client(SWOOLE_SOCK_TCP);
        $client->set(['socket_buffer_size' => 65536]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::same($client->send('begin'), 5);
        $pm->wait();
        $client->close();
        $pm->wait();
        Assert::same($closes->get(), 1);
        Assert::greaterThan($cancelled->get(), 0);
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $closes, $cancelled) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'send_yield' => true,
            'send_timeout' => 0,
            'socket_buffer_size' => 64 * 1024,
            'buffer_high_watermark' => 32 * 1024,
            'kernel_socket_send_buffer_size' => 65536,
            'log_file' => '/dev/null',
        ]);
        $server->on('workerStart', function () use ($pm) { $pm->wakeup(); });
        $server->on('receive', function (Server $server, int $fd) use ($pm, $cancelled) {
            for ($i = 0; $i < 8; $i++) {
                Coroutine::create(function () use ($server, $fd, $cancelled) {
                    $data = str_repeat('x', 16 * 1024);
                    // At most 32 MiB is submitted even if backpressure fails.
                    for ($n = 0; $n < 256; $n++) {
                        if (!@$server->send($fd, $data)) {
                            break;
                        }
                        Coroutine::sleep(0.001);
                    }
                    if (swoole_last_error() === SWOOLE_ERROR_CO_CANCELED) {
                        $cancelled->add();
                        // Reenters finish_close while the outer onClose cancels pending senders.
                        @$server->close($fd, true);
                    }
                });
            }
            // Allow pending sends to reach backpressure before closing the peer.
            Swoole\Timer::after(100, function () use ($pm) { $pm->wakeup(); });
        });
        $server->on('close', function () use ($pm, $closes) {
            Assert::same($closes->add(), 1);
            $pm->wakeup();
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
