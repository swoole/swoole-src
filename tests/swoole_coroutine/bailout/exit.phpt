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
        try
        {
            exit(0);
        } catch (Swoole\ExitException $e)
        {
            echo $e->getMessage()."\n";
        }
    });
});
$process->start();
$status = $process::wait();
if (Assert::isArray($status)) {
    list($pid, $code, $signal) = array_values($status);
    Assert::greaterThan($pid, 0);
    Assert::same($code, 0);
    Assert::same($signal, 0);
}
?>
--EXPECT--
swoole exit
shutdown
