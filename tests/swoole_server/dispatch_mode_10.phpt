--TEST--
swoole_server: concurrent load balancing avoids workers with active requests
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http\Client;
use Swoole\Http\Server;
use Swoole\Table;

$table = new Table(16);
$table->column('busy', Table::TYPE_INT);
$table->column('release', Table::TYPE_INT);
$table->create();
$table->set('control', ['release' => 0]);
for ($i = 0; $i < 4; $i++) {
    $table->set((string) $i, ['busy' => 0]);
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $table) {
    try {
        Coroutine\run(function () use ($pm, $table) {
            $finished = new Channel(3);
            try {
                for ($i = 0; $i < 3; $i++) {
                    Coroutine::create(function () use ($pm, $finished) {
                        $client = new Client('127.0.0.1', $pm->getFreePort());
                        $client->set(['timeout' => 5]);
                        try {
                            Assert::true($client->get('/hold'));
                            Assert::same($client->statusCode, 200);
                            $finished->push((int) $client->body);
                        } finally {
                            $client->close();
                        }
                    });
                    $deadline = microtime(true) + 2;
                    do {
                        $busy = [];
                        for ($worker = 0; $worker < 4; $worker++) {
                            if ($table->get((string) $worker, 'busy')) {
                                $busy[] = $worker;
                            }
                        }
                        if (count($busy) === $i + 1) {
                            break;
                        }
                        Coroutine::sleep(0.001);
                    } while (microtime(true) < $deadline);
                    if (!Assert::same(count($busy), $i + 1)) {
                        return;
                    }
                }
                $idle = array_values(array_diff([0, 1, 2, 3], $busy))[0];
                for ($i = 0; $i < 8; $i++) {
                    $client = new Client('127.0.0.1', $pm->getFreePort());
                    $client->set(['timeout' => 2]);
                    try {
                        Assert::true($client->get('/probe'));
                        Assert::same($client->statusCode, 200);
                        Assert::same((int) $client->body, $idle);
                    } finally {
                        $client->close();
                    }
                }
            } finally {
                $table->set('control', ['release' => 1]);
            }
            $workers = [];
            for ($i = 0; $i < 3; $i++) {
                $worker = $finished->pop(2);
                Assert::notSame($worker, false);
                $workers[] = $worker;
            }
            sort($workers);
            sort($busy);
            Assert::same($workers, $busy);
        });
    } finally {
        $table->set('control', ['release' => 1]);
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $table) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'dispatch_mode' => SWOOLE_DISPATCH_CONCURRENT_LB,
        'worker_num' => 4,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('request', function ($request, $response) use ($server, $table) {
        $worker = $server->getWorkerId();
        if ($request->server['request_uri'] === '/hold') {
            $table->set((string) $worker, ['busy' => 1]);
            $deadline = microtime(true) + 5;
            while (!$table->get('control', 'release') && microtime(true) < $deadline) {
                Coroutine::sleep(0.001);
            }
        }
        $response->end((string) $worker);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
