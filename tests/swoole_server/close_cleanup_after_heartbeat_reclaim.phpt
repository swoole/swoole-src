--TEST--
swoole_server: a late CLOSE cancels suspended senders after heartbeat reclaims the session
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Client;
use Swoole\Coroutine;
use Swoole\Server;

$cancelled = new Atomic();
$retired = new Atomic();
$closes = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(15);
$pm->parentFunc = function () use ($pm, $cancelled, $retired, $closes) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 65536]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    Assert::same($client->send('begin'), 5);
    $pm->wait();
    $deadline = microtime(true) + 12;
    while ($cancelled->get() === 0 && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($retired->get(), 1);
    Assert::greaterThan($cancelled->get(), 0);
    // Hard-deadline retirement cannot deliver a callback that was never claimed.
    Assert::same($closes->get(), 0);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $cancelled, $retired, $closes) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 2,
        'reactor_num' => 2,
        'hook_flags' => 0,
        'send_yield' => true,
        'send_timeout' => 0,
        'socket_buffer_size' => 65536,
        'buffer_high_watermark' => 32768,
        'kernel_socket_send_buffer_size' => 65536,
        'heartbeat_idle_time' => 1,
        'heartbeat_check_interval' => 1,
        'max_wait_time' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Server $server, int $fd) use ($pm, $cancelled, $retired) {
        for ($i = 0; $i < 8; $i++) {
            Coroutine::create(function () use ($server, $fd, $cancelled) {
                $data = str_repeat('x', 16384);
                for ($n = 0; $n < 256; $n++) {
                    if (!@$server->send($fd, $data)) {
                        if (swoole_last_error() === SWOOLE_ERROR_CO_CANCELED) {
                            $cancelled->add();
                        }
                        break;
                    }
                    Coroutine::sleep(0.001);
                }
            });
        }
        Swoole\Timer::after(150, function () use ($server, $fd, $pm, $retired) {
            $pm->wakeup();
            // Keep worker IPC queued beyond the reactor's hard reclamation deadline.
            usleep(7000000);
            $retired->set($server->getClientInfo($fd) === false ? 1 : 0);
        });
    });
    $server->on('close', function () use ($closes) { $closes->add(); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
