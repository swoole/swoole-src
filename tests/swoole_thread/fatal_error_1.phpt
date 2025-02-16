--TEST--
swoole_thread: fatal error
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = ProcessManager::exec(function () {
    include __DIR__ . '/fatal_error_1.inc';
});
$output = $pm->getChildOutput();
Assert::contains($output, "start child thread\n");
Assert::contains($output, "stop child thread\n");
Assert::contains($output, "Fatal error: Uncaught Swoole\Error: test");
?>
--EXPECT--
