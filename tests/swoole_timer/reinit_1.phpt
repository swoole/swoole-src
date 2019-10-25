--TEST--
swoole_timer: reinit [1]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Timer;

const RES_FILE = __DIR__ . '/result.txt';
file_put_contents(RES_FILE, "");

$pm = new ProcessManager;
$pm->setWaitTimeout(-1);
$pm->parentFunc = function ($pid) use ($pm) {
    $fp = fopen(RES_FILE, "rw");
    while (!feof($fp)) {
        $line = fgets($fp);
        if ($line) {
            echo $line;
        }
    }
    if (IS_MAC_OS) {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server("0.0.0.0", $pm->getFreePort());
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $server->on('start', function (Swoole\Server $server) use ($pm) {
        file_put_contents(RES_FILE, "start\n", FILE_APPEND);
        static $i = 0;
        $id = Timer::tick(100, function ($timerId) use (&$i, $server, $pm) {
            file_put_contents(RES_FILE, "timer 1\n", FILE_APPEND);
            if (($i++) == 4) {
                Timer::clear($timerId);
                $server->shutdown();
                $pm->wakeup();
            }
        });
    });

    static $j = 0;
    Timer::tick(50, function ($timerId) use (&$j) {
        file_put_contents(RES_FILE, "timer 2\n", FILE_APPEND);
        if (($j++) == 5) {
            Timer::clear($timerId);
        }
     });

    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
unlink(RES_FILE);
?>
--EXPECT--
start
timer 2
timer 2
timer 1
timer 2
timer 2
timer 1
timer 2
timer 2
timer 1
timer 1
timer 1
