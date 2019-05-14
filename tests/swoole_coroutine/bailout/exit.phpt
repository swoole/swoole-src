--TEST--
swoole_coroutine/bailout: error
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$process = new Swoole\Process(function () {
    register_shutdown_function(function () {
        echo 'shutdown' . PHP_EOL;
    });
    go(function () {
        exit(0);
    });
});
$process->start();
$status = $process::wait();
if (Assert::isArray($status)) {
    list($pid, $code, $signal) = array_values($status);
    Assert::greaterThan($pid, 0);
    Assert::eq($code, 0);
    Assert::eq($signal, 0);
}
?>
--EXPECT--
shutdown
