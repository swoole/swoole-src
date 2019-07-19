--TEST--
swoole_timer: #2697
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$server = new Swoole\Server('127.0.0.1', get_one_free_port());
$server->set(['log_file' => '/dev/null']);
$server->on('workerStart', function (Swoole\Server $server, int $worker_id) {
    Swoole\Timer::after(1000, function () {
        var_dump('never here');
    });
    Swoole\Timer::tick(1000, function () {
        var_dump('never here');
    });
    Swoole\Timer::clearAll();
    if ($worker_id === 0) {
        Swoole\Timer::after(10, function () use ($server) {
            $server->shutdown();
        });
    }
});
$server->on('receive', function () { });
$server->start();
echo "DONE\n";
?>
--EXPECT--
DONE
