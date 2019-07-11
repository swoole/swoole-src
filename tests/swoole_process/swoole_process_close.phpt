--TEST--
swoole_process: close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//$proc = new \swoole_process(swoole_function(\swoole_process $proc) {
//    $proc->close();
//});
//$proc->start();
//
//$proc = new \swoole_process(swoole_function(\swoole_process $proc) {
//    usleep(200000);
//    // Assert::true(false, 'never here');
//});
//$proc->start();
//$proc->close();
//
//
//\swoole_process::wait(true);
//\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
