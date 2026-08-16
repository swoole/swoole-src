--TEST--
swoole_process: ProcessManager readiness timeouts fail
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->setWaitTimeout(1);
$pm->childFunc = function (): void {
    sleep(60);
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
try {
    $pm->run();
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'ProcessManager parent timed out waiting for a readiness signal');
}
Assert::false(@Process::kill($pm->getChildPid(), 0));
Assert::false(Process::wait(false));

$pm = new ProcessManager();
$pm->setWaitTimeout(1);
$pm->childFunc = function (): void {
};
$pm->parentFunc = function (): void {
};
$pm->parentFirst();
$pm->run(true);
$pm->expectExitCode(255);
Assert::contains($pm->getChildOutput(), 'ProcessManager child timed out waiting for a readiness signal');

echo "DONE\n";
?>
--EXPECT--
DONE
