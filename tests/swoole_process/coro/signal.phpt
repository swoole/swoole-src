--TEST--
swoole_process/coro: signal with coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;
use Swoole\Runtime;
use Swoole\Event;

$process = new Process(function ($process) {
    Co::sleep(.2);
}, false, SOCK_DGRAM, true);

$process->start();

Process::signal(SIGCHLD, function ($sig) {
    while ($ret = Process::wait(false)) {
        echo "PID={$ret['pid']}\n";
    }
});

go(function () {
    Co::sleep(.3);
    echo "END\n";
});

Event::wait();

?>
--EXPECTF--
PID=%d
END
