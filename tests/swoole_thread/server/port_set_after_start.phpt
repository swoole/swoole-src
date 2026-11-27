--TEST--
swoole_thread/server: the master cannot change published port settings
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_defined('SWOOLE_THREAD');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Server;
use Swoole\Thread;

Assert::setThrowException(true);
$ports = [get_constant_port(__FILE__), get_constant_port(__FILE__ . 'secondary')];
$server = new Server('127.0.0.1', $ports[0], SWOOLE_THREAD);
$server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
$server->listen('127.0.0.1', $ports[1], SWOOLE_SOCK_TCP);
foreach ($server->ports as $port) {
    Assert::same($port->set(['open_eof_check' => true, 'package_eof' => "\n"]), Thread::getInfo()['is_main_thread']);
}
$server->on('Start', function (Server $server) use ($ports) {
    try {
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
        foreach ($ports as $port) {
            $client = new Client(SWOOLE_SOCK_TCP);
            try {
                Assert::true($client->connect('127.0.0.1', $port, 5));
                Assert::same($client->send("hello\n"), 6);
                Assert::same($client->recv(), "hello\n");
            } finally {
                $client->close();
            }
        }
    } finally {
        $server->shutdown();
    }
});
$server->on('Receive', fn (Server $server, int $fd, int $reactorId, string $data) => $server->send($fd, $data));
$server->start();
if (Thread::getInfo()['is_main_thread']) {
    echo "DONE\n";
}
?>
--EXPECT--
DONE
