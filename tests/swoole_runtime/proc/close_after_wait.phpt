--TEST--
swoole_runtime/proc: proc_close() after wait
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

include_once dirname(__FILE__) . "/proc_open_pipes.inc";
Swoole\Runtime::enableCoroutine();

Co\run(function() {
    $descriptorspec = array(
        0 => array("pipe", "/dev/null"),
        1 => array("pipe", "/dev/null"),
        2 => array("pipe", "/dev/null")
    );

    $proc = proc_open('/bin/sleep 30', $descriptorspec, $pipes);
    Assert::notEmpty($proc);
    echo "wait begin\n";

    go(function() use($proc) {
        usleep(100000);
        proc_terminate($proc);
    });

    $info = Co\System::wait();
    Assert::notEmpty($info);
    echo "wait end\n";
    proc_close($proc);
    echo "proc_close end\n";
});
?>
--EXPECTF--
wait begin
wait end
proc_close end
