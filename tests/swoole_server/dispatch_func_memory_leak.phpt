--TEST--
swoole_server: dispatch_func_memory_leak
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_TCP);
            Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
            Assert::assert($client->send(str_repeat(get_safe_random(1024), 32)));
        });
    }
    Swoole\Event::wait();
    sleep(1);
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $mem_size = 0;
    function dispatch_packet($server, $fd, $type, $data)
    {
        global $mem_size;
        if ($mem_size) {
            Assert::assert($mem_size + 128 * 1024 > memory_get_usage());
        } else {
            $mem_size = memory_get_usage();
        }
        return str_repeat('0', 1024 * 1024);
    }

    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $server->set([
        'worker_num' => rand(4, 8),
        'log_file' => '/dev/null',
        'reactor_num' => 1,
        'dispatch_func' => 'dispatch_packet',
        'trace_flags' => SWOOLE_TRACE_EVENT,
        'log_level' => 0,
    ]);
    $server->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Server $server, $data, $client) {

    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
