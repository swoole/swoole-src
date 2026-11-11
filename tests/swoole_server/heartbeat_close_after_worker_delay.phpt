--TEST--
swoole_server: heartbeat preserves the session and cancels suspended senders after a worker delay
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
$retained = new Atomic();
$closes = new Atomic();
$pm = new ProcessManager();
$pm->setWaitTimeout(15);
$pm->parentFunc = function () use ($pm, $cancelled, $retained, $closes) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 65536]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    Assert::same($client->send('begin'), 5);
    $pm->wait();
    $deadline = microtime(true) + 12;
    while (($cancelled->get() === 0 || $closes->get() === 0) && microtime(true) < $deadline) {
        usleep(10000);
    }
    Assert::same($retained->get(), 1);
    Assert::greaterThan($cancelled->get(), 0);
    Assert::same($closes->get(), 1);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $cancelled, $retained, $closes) {
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
        'max_wait_time' => 3,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Server $server, int $fd) use ($pm, $cancelled, $retained) {
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
        Swoole\Timer::after(150, function () use ($server, $fd, $pm, $retained) {
            $pm->wakeup();
            // Block for less than the five-second grace measured from CLOSE notification.
            usleep(4200000);
            $retained->set(is_array($server->getClientInfo($fd)) ? 1 : 0);
        });
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
