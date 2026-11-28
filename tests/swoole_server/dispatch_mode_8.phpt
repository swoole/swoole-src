--TEST--
swoole_server: dispatch_mode = 8 chooses an idle worker and preserves connection affinity
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine\Client;
use Swoole\Coroutine\System;
use Swoole\Server;
use Swoole\Table;
use Swoole\Timer;

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

Assert::setThrowException(true);
const WORKERS = 4;
const REQUESTS = 200;

// Coroutine load is published at the end of a worker reactor iteration. A timer created
// by another timer cannot run in the same timer round, so acknowledge only after publication.
function afterLoadPublication(callable $callback): void
{
    Timer::after(1, static function () use ($callback) { Timer::after(1, $callback); });
}

$table = new Table(64);
$table->column('count', Table::TYPE_INT);
$table->create();
$port = new Atomic();
$started = new Atomic();
$warmupComplete = new Atomic();
$releaseMask = new Atomic();
$pm = new SwooleTest\ProcessManager;
$pm->magic_code = rand(10000000, 90000000);
$pm->parentFunc = function () use ($pm, $table, $port, $started, $warmupComplete, $releaseMask) {
    try {
        run(function () use ($pm, $port, $started, $warmupComplete, $releaseMask) {
            $deadline = hrtime(true) + 5e9;
            while ($started->get() !== WORKERS && hrtime(true) < $deadline) {
                System::sleep(0.001);
            }
            Assert::same($started->get(), WORKERS);
            $connect = static function () use ($port): Client {
                $client = new Client(SWOOLE_SOCK_TCP);
                $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
                Assert::true($client->connect('127.0.0.1', $port->get(), 5));
                return $client;
            };
            $request = static function (Client $client, bool $probe = false) use ($pm): void {
                $data = [
                    'name' => __FILE__,
                    'sid' => $pm->magic_code,
                    'content' => str_repeat('A', 8192 * rand(1, 3)),
                    'probe' => $probe,
                ];
                Assert::greaterThan($client->send(serialize($data) . "\r\n\r\n"), 0);
            };

            // Keep one onConnect coroutine resident on each worker. Each subsequent connection
            // must choose a still-idle worker, rather than relying on random aggregate variance.
            $held = [];
            for ($i = 0; $i < WORKERS; $i++) {
                $client = $connect();
                $ready = $client->recv();
                Assert::assert(preg_match('/^READY:([0-3])\n$/', $ready) === 1);
                $workerId = (int) substr($ready, 6);
                Assert::false(isset($held[$workerId]));
                $held[$workerId] = $client;
            }
            Assert::same(count($held), WORKERS);
            $warmupComplete->set(1);

            // Free worker 2 and wait until its zero load is published. New connections must
            // choose it, while requests on the four existing connections stay on their owners.
            $releaseMask->set(1 << 2);
            Assert::same($held[2]->recv(), "RELEASED\n");
            $probe = $connect();
            $request($probe, true);
            Assert::same($probe->recv(), "2\n");
            $probe->close();
            foreach ($held as $workerId => $client) {
                $request($client, true);
                Assert::same($client->recv(), "{$workerId}\n");
            }

            for ($i = 0; $i < REQUESTS; $i++) {
                go(static function () use ($connect, $request) {
                    $client = $connect();
                    $request($client);
                    Assert::same($client->recv(), "SUCCESS\n");
                    $client->close();
                });
            }
        });
        $counts = array_column(iterator_to_array($table), 'count');
        Assert::same(count($counts), WORKERS);
        Assert::same(array_sum($counts), WORKERS + 1 + REQUESTS);
    } finally {
        $releaseMask->set((1 << WORKERS) - 1);
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $table, $port, $started, $warmupComplete, $releaseMask) {
    $server = new Server('127.0.0.1', 0, SWOOLE_PROCESS);
    $port->set($server->port);
    $server->set([
        'package_eof' => "\r\n\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
        'dispatch_mode' => SWOOLE_DISPATCH_CO_CONN_LB,
        'package_max_length' => 1024 * 1024 * 2,
        'worker_num' => WORKERS,
        'log_file' => '/dev/null',
        'reload_async' => true,
    ]);
    $server->on('Start', function () use ($pm) { $pm->wakeup(); });
    $server->on('WorkerStart', function () use ($started) { $started->add(); });
    $server->on('Connect', function (Server $server, int $fd) use ($table, $warmupComplete, $releaseMask) {
        $workerId = $server->getWorkerId();
        $table->incr($workerId, 'count');
        if ($warmupComplete->get()) {
            // Exercise receive delivery while onConnect is suspended, without a random half-second sleep.
            System::sleep(0.005);
            return;
        }
        afterLoadPublication(static function () use ($server, $fd, $workerId) {
            Assert::true($server->send($fd, "READY:{$workerId}\n"));
        });
        while (($releaseMask->get() & (1 << $workerId)) === 0) {
            System::sleep(0.001);
        }
        if ($workerId === 2) {
            afterLoadPublication(static function () use ($server, $fd) {
                Assert::true($server->send($fd, "RELEASED\n"));
            });
        }
    });
    $server->on('Receive', function (Server $server, int $fd, int $rid, string $data) use ($pm) {
        Assert::same($server->getClientInfo($fd)['worker_id'], $server->getWorkerId());
        $packet = unserialize(substr($data, 0, -4));
        Assert::isArray($packet);
        Assert::same($packet['sid'], $pm->magic_code);
        $response = $packet['probe'] ? $server->getWorkerId() . "\n" : "SUCCESS\n";
        Assert::true($server->send($fd, $response));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
