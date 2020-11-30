--TEST--
swoole_coroutine/async_callback: signal
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;

Co\run(function () {
    Process::signal(SIGUSR1, function ($signo) {
        Co::sleep(0.5);
        var_dump($signo);
    });

    Co::sleep(0.01);
    Process::kill(posix_getpid(), SIGUSR1);
    Co::sleep(0.02);
});
?>
--EXPECT--
int(10)
