--TEST--
swoole_timer: timer in master (base)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->setWaitTimeout(-1);
$pm->parentFunc = function () use ($pm) {
    if (IS_MAC_OS) {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('start', function (Swoole\Server $server) use ($pm) {
        echo "start\n";
        $id = Swoole\Timer::tick(100, function () {
            echo "timer 1\n";
        });
        Swoole\Timer::after(300, function () use ($id, $server, $pm) {
            echo "timer 2\n";
            Swoole\Timer::clear($id);
            Swoole\Timer::tick(50, function ($id) use ($server, $pm) {
                static $i = 0;
                echo "timer 3\n";
                $i++;
                if ($i > 4) {
                    echo "end\n";
                    Swoole\Timer::clear($id);
                    $pm->wakeup();
                    $server->shutdown();
                }
            });
        });
    });
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
start
timer 1
timer 1
timer 1
timer 2
timer 3
timer 3
timer 3
timer 3
timer 3
end
