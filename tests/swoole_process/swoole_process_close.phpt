--TEST--
swoole_process: close
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

//$proc = new Swoole\Process(swoole_function(Swoole\Process $proc) {
//    $proc->close();
//});
//$proc->start();
//
//$proc = new Swoole\Process(swoole_function(Swoole\Process $proc) {
//    usleep(200000);
//    // Assert::true(false, 'never here');
//});
//$proc->start();
//$proc->close();
//
//
//\Swoole\Process::wait(true);
//\Swoole\Process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
