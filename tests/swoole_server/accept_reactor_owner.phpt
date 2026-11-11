--TEST--
swoole_server: the fd owner initializes accepted connections before immediate onConnect close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Server;
use function Swoole\Coroutine\run;

const CONNECTIONS = 128;
$connects = new Atomic();
$closes = new Atomic();
$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm, $connects, $closes) {
    run(function () use ($pm) {
        $clients = [];
        for ($i = 0; $i < CONNECTIONS; $i++) {
            $clients[] = go(function () use ($pm) {
                $client = new Client(SWOOLE_SOCK_TCP);
                $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
                Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
                $identity = json_decode($client->recv(), true);
                Assert::same($identity['socket_fd'] % 2, $identity['reactor_id']);
                Assert::same($client->recv(), '');
                $client->close();
            });
        }
        Coroutine::join($clients);
    });
    Assert::same($connects->get(), CONNECTIONS);
    Assert::same($closes->get(), CONNECTIONS);
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $connects, $closes) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 2,
        'reactor_num' => 2,
        'enable_delay_receive' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function (Server $server, int $worker) use ($pm) {
        if ($worker === 0) {
            $pm->wakeup();
        }
    });
    $server->on('connect', function (Server $server, int $fd, int $reactor) use ($connects) {
        $info = $server->getClientInfo($fd);
        Assert::same($info['reactor_id'], $reactor);
        Assert::same($info['socket_fd'] % 2, $reactor);
        Assert::true($server->send($fd, json_encode($info) . "\n"));
        $connects->add();
        Assert::true($server->close($fd));
    });
    $server->on('close', function () use ($closes) { $closes->add(); });
    $server->on('receive', function () { Assert::true(false, 'receive must remain delayed'); });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
