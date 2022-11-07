--TEST--
swoole_coroutine/exception: fatal error
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Process;

$process = new Process(function () {
    register_shutdown_function(function () {
        echo "shutdown\n";
    });
    Co\run(function () {
        call_func_not_exists();
        sleep(1);
        echo "co end\n";
    });
}, true, SOCK_STREAM);
$process->start();
$status = Process::wait();
if (Assert::isArray($status)) {
    list($pid, $code, $signal) = array_values($status);
    Assert::greaterThan($pid, 0);

    $out = $process->read();
    Assert::contains($out, 'Uncaught Error: Call to undefined function call_func_not_exists()');
    Assert::contains($out, 'shutdown');
    Assert::notContains($out, 'co end');
    Assert::same($code, 255);
}
?>
--EXPECT--
