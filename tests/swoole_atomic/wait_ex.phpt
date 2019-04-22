--TEST--
swoole_atomic: wakeup & wait ex
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$atomic = new Swoole\Atomic();
$server = new Swoole\Http\Server('127.0.0.1', get_one_free_port());
$server->set(['worker_num' => 4, 'log_file' => '/dev/null']);
$server->on('WorkerStart', function (Swoole\Http\Server $server, int $wid) use ($atomic) {
    if ($wid === 0) {
        sleep(1);
        $atomic->wakeup(3);
        sleep(1);
        $server->shutdown();
    } else {
        $s = microtime(true);
        echo "sleeping...\n";
        $atomic->wait(-1);
        echo "I'm wide awake\n";
        $s = microtime(true) - $s;
        time_approximate(1, $s, 0.2);
    }
});
$server->on('Request', function () { });
$server->start();
?>
--EXPECT--
sleeping...
sleeping...
sleeping...
I'm wide awake
I'm wide awake
I'm wide awake
