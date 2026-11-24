--TEST--
swoole_server: close and buffer callbacks run from the event loop without nesting
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
    foreach ([false, true] as $enableCoroutine) {
        foreach (['close', 'peer', 'full', 'empty'] as $action) {
            $closes = new Atomic();
            $fulls = new Atomic();
            $empties = new Atomic();
            $pm = new ProcessManager();
            $pm->setWaitTimeout(5);
            $pm->parentFunc = function () use ($pm, $action, $closes, $fulls, $empties) {
                $client = new Client(SWOOLE_SOCK_TCP);
                Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                Assert::same($client->send('begin'), 5);
                if ($action === 'peer') {
                    Assert::same($client->recv(), 'ready');
                    $client->close();
                }
                Assert::true($pm->wait());
                if ($action === 'empty') {
                    // Drain only after Full has run, then wait for the deferred close callback.
                    while ($client->recv() !== '') {
                        Assert::same($client->errCode, 0);
                    }
                    Assert::true($pm->wait());
                }
                Assert::same($closes->get(), 1);
                Assert::same($fulls->get(), in_array($action, ['close', 'peer'], true) ? 0 : 1);
                Assert::same($empties->get(), $action === 'empty' ? 1 : 0);
                if ($action !== 'peer') {
                    $client->close();
                }
                $pm->kill();
            };
            $pm->childFunc = function () use ($pm, $mode, $enableCoroutine, $action, $closes, $fulls, $empties) {
                $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
                $server->set([
                    'worker_num' => 1,
                    'enable_coroutine' => $enableCoroutine,
                    'event_object' => $enableCoroutine,
                    'send_yield' => false,
                    'socket_buffer_size' => 2 * 1024 * 1024,
                    'kernel_socket_send_buffer_size' => 65536,
                    'buffer_high_watermark' => 32768,
                    'buffer_low_watermark' => 16384,
                    'log_file' => '/dev/null',
                ]);
                $inside = false;
                $received = false;
                $server->on('WorkerStart', fn () => $pm->wakeup());
                $server->on('Receive', function (Server $server, $event) use (&$inside, &$received, $action) {
                    $fd = is_object($event) ? $event->fd : $event;
                    $inside = true;
                    if ($action === 'close') {
                        Assert::true($server->close($fd));
                    } elseif ($action === 'peer') {
                        Assert::true($server->send($fd, 'ready'));
                    } else {
                        Assert::true($server->send($fd, str_repeat('x', 1024 * 1024)));
                    }
                    $received = true;
                    $inside = false;
                });
                $server->on('BufferFull', function (Server $server, int $fd) use (
                    $pm, &$inside, &$received, $action, $fulls
                ) {
                    Assert::false($inside);
                    Assert::true($received);
                    Assert::same(Coroutine::getCid(), -1);
                    Assert::same($fulls->add(), 1);
                    $inside = true;
                    if ($action === 'full') {
                        Assert::true($server->close($fd, true));
                    } else {
                        $pm->wakeup();
                    }
                    $inside = false;
                });
                $server->on('BufferEmpty', function (Server $server, int $fd) use (
                    &$inside, $action, $fulls, $empties
                ) {
                    Assert::false($inside);
                    Assert::same(Coroutine::getCid(), -1);
                    Assert::same($action, 'empty');
                    Assert::same($fulls->get(), 1);
                    Assert::same($empties->add(), 1);
                    $inside = true;
                    Assert::true($server->close($fd));
                    $inside = false;
                });
                $server->on('Close', function (Server $server, $event, ?int $reactorId = null) use (
                    $pm, &$inside, &$received, $enableCoroutine, $action, $closes
                ) {
                    Assert::false($inside);
                    Assert::true($received);
                    if ($enableCoroutine) {
                        Assert::same(Coroutine::getPcid(), -1);
                    } else {
                        Assert::same(Coroutine::getCid(), -1);
                    }
                    $reactorId = is_object($event) ? $event->reactor_id : $reactorId;
                    if ($action === 'peer') {
                        Assert::greaterThanEq($reactorId, 0);
                    } else {
                        Assert::same($reactorId, -1);
                    }
                    Assert::same($closes->add(), 1);
                    $pm->wakeup();
                });
                $server->start();
            };
            $pm->childFirst();
            $pm->run();
        }
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
