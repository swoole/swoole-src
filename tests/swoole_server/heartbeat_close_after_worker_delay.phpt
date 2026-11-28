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

Assert::setThrowException(true);
$cancelled = new Atomic();
$retained  = new Atomic();
$closes    = new Atomic();
$port      = new Atomic();
$started   = new Atomic();
$release   = new Atomic();
$finished  = new Atomic();
$session   = new Atomic();
$closing   = new Atomic();
$pm        = new ProcessManager();
$pm->setWaitTimeout(10);
$pm->parentFunc = function () use ($pm, $port, $started, $release, $finished, $closing, $cancelled, $retained, $closes) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['socket_buffer_size' => 65536]);
    try {
        $deadline = hrtime(true) + 5e9;
        while ($started->get() !== 2 && hrtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($started->get(), 2);
        Assert::true($client->connect('127.0.0.1', $port->get(), 5));
        Assert::same($client->send('begin'), 5);
        // The worker is now synchronously blocked with send-yield coroutines pending.
        $pm->wait();
        // Do not drain the socket: doing so would relieve backpressure and wake senders
        // through BufferEmpty before CLOSE can cancel them.
        Assert::true($closing->wait(5));
        Assert::same($closes->get(), 0);
        // Start the observation window only after heartbeat has requested the close.
        // Keep the live worker blocked beyond max_wait_time without a blind 4.2-second delay.
        usleep(1100000);
        Assert::same($closes->get(), 0);
        $release->wakeup();
        Assert::true($finished->wait(5));
        Assert::same($retained->get(), 1);
        Assert::greaterThan($cancelled->get(), 0);
        Assert::same($closes->get(), 1);
    } finally {
        $release->wakeup();
        $client->close();
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm, $port, $started, $release, $finished, $session, $closing, $cancelled, $retained, $closes) {
    $server = new Server('127.0.0.1', 0, SWOOLE_PROCESS);
    $port->set($server->port);
    $server->set([
        'worker_num'                     => 2,
        'reactor_num'                    => 2,
        'hook_flags'                     => 0,
        'send_yield'                     => true,
        'send_timeout'                   => 0,
        'socket_buffer_size'             => 65536,
        'buffer_high_watermark'          => 32768,
        'kernel_socket_send_buffer_size' => 65536,
        'heartbeat_idle_time'            => 1,
        'heartbeat_check_interval'       => 1,
        'max_wait_time'                  => 1,
        'log_file'                       => '/dev/null',
    ]);
    $server->on('start', function (Server $server) use ($pm, $session, $closing) {
        $pm->wakeup();
        // The master keeps running while the event worker is blocked. exists() becomes false
        // at the first close request, while getClientInfo() can still see the retained session.
        Swoole\Timer::tick(5, function ($timerId) use ($server, $session, $closing) {
            $fd = $session->get();
            if ($fd && !$server->exists($fd)) {
                Swoole\Timer::clear($timerId);
                $closing->wakeup();
            }
        });
    });
    $server->on('workerStart', function () use ($started) { $started->add(); });
    $server->on('receive', function (Server $server, int $fd) use ($pm, $release, $session, $cancelled, $retained) {
        $session->set($fd);
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
        Swoole\Timer::after(150, function () use ($server, $fd, $pm, $release, $retained) {
            $pm->wakeup();
            Assert::true($release->wait(10));
            $retained->set(is_array($server->getClientInfo($fd)) ? 1 : 0);
        });
    });
    $server->on('close', function (Server $server, int $fd) use ($closes, $finished) {
        Assert::isArray($server->getClientInfo($fd));
        Assert::same($closes->add(), 1);
        $finished->wakeup();
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
