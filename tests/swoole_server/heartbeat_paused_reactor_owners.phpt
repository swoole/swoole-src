--TEST--
swoole_server: heartbeat scans paused connections on both owner reactors
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Server;

const CONNECTIONS = 8;
$closes = new Atomic();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $closes) {
    $clients = [];
    $owners = [];
    for ($i = 0; $i < CONNECTIONS; $i++) {
        $client = stream_socket_client('tcp://127.0.0.1:' . $pm->getFreePort(), $errno, $errstr, 5);
        stream_set_timeout($client, 10);
        $info = json_decode(fgets($client), true);
        Assert::same($info['socket_fd'] % 2, $info['reactor_id']);
        $owners[$info['reactor_id']] = true;
        $clients[] = $client;
    }
    Assert::same(count($owners), 2);
    foreach ($clients as $client) {
        Assert::same(stream_get_contents($client), '');
        Assert::false(stream_get_meta_data($client)['timed_out']);
        fclose($client);
    }
    // Heartbeat shutdown can deliver EOF before the workers execute their close callbacks.
    Assert::true($pm->wait());
    Assert::same($closes->get(), CONNECTIONS);
    usleep(1100000);
    Assert::same($closes->get(), CONNECTIONS);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $closes) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 2,
        'reactor_num' => 2,
        'heartbeat_idle_time' => 1,
        'heartbeat_check_interval' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server, int $worker) use ($pm) {
        if ($worker === 0) {
            $pm->wakeup();
        }
    });
    $server->on('connect', function (Server $server, int $fd) {
        Assert::true($server->pause($fd));
        Assert::true($server->send($fd, json_encode($server->getClientInfo($fd)) . "\n"));
    });
    $server->on('receive', function () { Assert::true(false, 'connection remains paused'); });
    $server->on('close', function () use ($pm, $closes) {
        if ($closes->add() === CONNECTIONS) {
            $pm->wakeup();
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
