--TEST--
swoole_server: connect and close callbacks run once when peer and application close race
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine\Client;
use Swoole\Server;
use Swoole\Table;
use Swoole\Timer;
use function Swoole\Coroutine\run;

const CONNECTIONS = 96;
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $connects = new Atomic();
    $closes = new Atomic();
    $sessions = new Table(1024);
    $sessions->column('connects', Table::TYPE_INT);
    $sessions->column('closes', Table::TYPE_INT);
    $sessions->create();
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $connects, $closes, $sessions) {
        run(function () use ($pm, $closes) {
            // Repeated waves also exercise reuse of descriptor slots with new session ids.
            for ($wave = 0; $wave < 3; $wave++) {
                $clients = [];
                for ($i = 0; $i < CONNECTIONS / 3; $i++) {
                    $clients[] = go(function () use ($pm, $i) {
                        $client = new Client(SWOOLE_SOCK_TCP);
                        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                        Assert::same($client->send('hello'), 5);
                        Assert::same($client->recv(), 'ready');
                        Assert::same($client->send($i % 2 ? 'reset' : 'close'), 5);
                        // FIN and the server's normal/reset close may arrive in either order.
                        if ($i % 3) {
                            Swoole\Coroutine::sleep(($i % 3) / 1000);
                        }
                        $client->close();
                    });
                }
                Swoole\Coroutine::join($clients);
            }
            $deadline = microtime(true) + 10;
            while ($closes->get() < CONNECTIONS && microtime(true) < $deadline) {
                Swoole\Coroutine::sleep(0.01);
            }
        });
        Assert::same($connects->get(), CONNECTIONS);
        Assert::same($closes->get(), CONNECTIONS);
        Assert::same(count($sessions), CONNECTIONS);
        foreach ($sessions as $row) {
            Assert::same($row['connects'], 1);
            Assert::same($row['closes'], 1);
        }
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $connects, $closes, $sessions) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 2, 'log_file' => '/dev/null']);
        $server->on('workerStart', function (Server $server, int $worker) use ($pm) {
            if ($worker === 0) {
                $pm->wakeup();
            }
        });
        $server->on('connect', function (Server $server, int $fd) use ($connects, $sessions) {
            Assert::false($sessions->exists((string) $fd));
            $sessions->set((string) $fd, ['connects' => 1, 'closes' => 0]);
            $connects->add();
        });
        $server->on('receive', function (Server $server, int $fd, int $reactor, string $data) {
            if ($data === 'hello') {
                Assert::true($server->send($fd, 'ready'));
                return;
            }
            Timer::after(1, function () use ($server, $fd, $data) {
                if ($server->exists($fd)) {
                    @$server->close($fd, $data === 'reset');
                }
            });
        });
        $server->on('close', function (Server $server, int $fd) use ($closes, $sessions) {
            Assert::true($sessions->exists((string) $fd));
            Assert::same($sessions->incr((string) $fd, 'closes'), 1);
            $closes->add();
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
