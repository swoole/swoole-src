--TEST--
swoole_process: alarm
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_process::signal(SIGALRM, function () {
    static $i = 0;
    echo "#{$i}\talarm\n";
    $i++;
    if ($i > 10) {
        swoole_process::alarm(-1);
        swoole_process::signal(SIGALRM, null);
        swoole_event_exit();
    }
});

//100ms
swoole_process::alarm(10 * 1000);
swoole_event_wait();

?>
--EXPECT--
#0	alarm
#1	alarm
#2	alarm
#3	alarm
#4	alarm
#5	alarm
#6	alarm
#7	alarm
#8	alarm
#9	alarm
#10	alarm
