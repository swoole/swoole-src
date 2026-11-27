--TEST--
swoole_server_port: native settings cannot change after startup in BASE or PROCESS mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Client;
use Swoole\Server;

Assert::setThrowException(true);
function assertPortSettingsFrozen(Server $server): void
{
    foreach ($server->ports as $port) {
        $settings = $port->setting;
        try {
            $port->set(['backlog' => 256, 'package_eof' => '!']);
            Assert::true(false, 'runtime port configuration must throw');
        } catch (Swoole\Exception $exception) {
            Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
            Assert::contains($exception->getMessage(), 'server is running');
        }
        Assert::same($port->setting, $settings);
    }
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->initFreePorts(2);
    $pm->parentFunc = function () use ($pm) {
        try {
            Coroutine\run(function () use ($pm) {
                foreach ([0, 1] as $index) {
                    $client = new Client(SWOOLE_SOCK_TCP);
                    try {
                        Assert::true($client->connect('127.0.0.1', $pm->getFreePort($index), 5));
                        Assert::same($client->send("hello\n"), 6);
                        Assert::same($client->recv(), "hello\n");
                    } finally {
                        $client->close();
                    }
                }
            });
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'reactor_num' => 1, 'log_file' => '/dev/null']);
        $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
        foreach ($server->ports as $port) {
            Assert::true($port->set(['open_eof_check' => true, 'package_eof' => "\n"]));
        }
        $server->on('Start', 'assertPortSettingsFrozen');
        $server->on('WorkerStart', function (Server $server) use ($pm) {
            assertPortSettingsFrozen($server);
            $pm->wakeup();
        });
        $server->on('Receive', fn (Server $server, int $fd, int $reactorId, string $data) => $server->send($fd, $data));
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
