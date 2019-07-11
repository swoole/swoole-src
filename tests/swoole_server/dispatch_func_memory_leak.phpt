--TEST--
swoole_server: dispatch_func_memory_leak
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm) {
            $client = new Co\Client(SWOOLE_SOCK_TCP);
            Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
            Assert::assert($client->send(str_repeat(get_safe_random(1024), 32)));
        });
    }
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $mem_size = 0;
    function dispatch_packet($server, $fd, $type, $data)
    {
        global $mem_size;
        if($mem_size){
            Assert::assert($mem_size + 128 * 1024 > memory_get_usage());
        }else {
            $mem_size = memory_get_usage();
        }
        return str_repeat('0', 1024 * 1024);
    }

    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $server->set([
        'worker_num' => rand(4, 8),
        'log_file' => '/dev/null',
        'dispatch_func' => 'dispatch_packet'
    ]);
    $server->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, $data, $client) {

    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
