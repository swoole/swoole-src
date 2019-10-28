--TEST--
swoole_runtime/proc: proc_open
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
<?php # vim:syn=php
if (!is_executable("/bin/cat")) exit('skip');
if (!function_exists("proc_open")) exit('skip proc_open() is not available');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

go(function() {
    $ds = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );

    $cat = proc_open(
        "/bin/cat",
        $ds,
        $pipes
    );

    proc_close($cat);
    echo "I didn't segfault!\n";
});

swoole_event::wait();
?>
--EXPECT--
I didn't segfault!
