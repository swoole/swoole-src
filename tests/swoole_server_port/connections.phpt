--TEST--
swoole_server_port: connections
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Scheduler;
use Swoole\WebSocket\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm) {
    $sch = new Scheduler();
    $ready = new Swoole\Coroutine\Channel(8);
    $release = new Swoole\Coroutine\Channel(1);
    $clients = [];
    $conns = [[], []];

    foreach ([0, 0, 0, 1, 1, 0, 0, 1] as $index => $port) {
        $sch->add(function () use ($pm, $ready, $release, &$clients, &$conns, $index, $port) {
            $client = new Client(TCP_SERVER_HOST, $pm->getFreePort($port));
            Assert::true($client->upgrade('/'));
            $frame = $client->recv();
            Assert::true($frame !== false);
            $conns[$port][] = $frame->data;
            $clients[$index] = $client;
            $ready->push(true);
            // Keep every connection alive until all three iterator checks finish.
            $release->pop();
            $client->close();
        });
    }
    $sch->add(function () use ($pm, $ready, $release, &$clients, &$conns) {
        try {
            for ($i = 0; $i < 8; $i++) {
                Assert::true($ready->pop(5));
            }
            $queries = [
                [5, 'all', array_merge($conns[0], $conns[1])],
                [6, 'port-0', $conns[0]],
                [7, 'port-1', $conns[1]],
            ];
            foreach ($queries as [$index, $query, $expected]) {
                Assert::true($clients[$index]->push($query));
                $frame = $clients[$index]->recv();
                Assert::true($frame !== false);
                $result = json_decode($frame->data);
                Assert::eq($result->count, count($expected));
                Assert::eq(array_arrange($result->list), array_arrange($expected));
            }
        } finally {
            $release->close();
            $pm->kill();
        }
    });
    $sch->start();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('0.0.0.0', $pm->getFreePort(0), SWOOLE_PROCESS);
    $server->set([
        Constant::OPTION_LOG_FILE => '/dev/null',
        Constant::OPTION_WORKER_NUM => 1,
    ]);
    $server->on('open', function (Server $server, $request) {
        $server->push($request->fd, $request->fd);
    });
    $server->on(
        Constant::EVENT_WORKER_START,
        function () use ($pm) {
            $pm->wakeup();
        }
    );

    $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);

    $server->on(
        'message',
        function (Server $server, $frame) {
            if ($frame->data == 'all') {
                $iterator = $server->connections;
            } elseif ($frame->data == 'port-0') {
                $iterator = $server->ports[0]->connections;
            } elseif ($frame->data == 'port-1') {
                $iterator = $server->ports[1]->connections;
            } else {
                return;
            }

            $data['count'] = count($iterator);
            $data['list'] = array_values(iterator_to_array($iterator));
            $server->push($frame->fd, json_encode($data));
        }
    );

    $server->on('close', function ($ser, $fd) {});

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
