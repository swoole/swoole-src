--TEST--
swoole_coroutine/exception: defer 1
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Coroutine;
use Swoole\Process;

$process = new Process(function () {
    register_shutdown_function(function () {
        echo "shutdown\n";
    });

    Co\run(function () {
        echo "co-1 begin\n";

        Coroutine::create(static function () {
            echo "co-2 begin\n";
            Coroutine::defer(static function () {
                echo "defer task begin\n";
                throw new Exception();
                echo "defer task end\n";
            });
            throw new Exception();
            echo "co-2 end\n";
        });

        echo "co-1 end\n";
    });
    echo "done\n";
}, true, SOCK_STREAM);
$process->start();
$status = Process::wait();
if (Assert::isArray($status)) {
    list($pid, $code, $signal) = array_values($status);
    Assert::greaterThan($pid, 0);

    $out = $process->read();
    Assert::contains($out, 'co-1 begin');
    Assert::contains($out, 'co-2 begin');
    Assert::contains($out, 'defer task begin');
    Assert::contains($out, 'shutdown');
    Assert::contains($out, 'Fatal error: Uncaught Exception');
    Assert::notContains($out, 'co-1 end');
    Assert::same($code, 255);
}
?>
--EXPECTF--
