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
$pm->setWaitTimeout(0.1);
try {
    $pm->wait();
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'ProcessManager did not receive a wakeup within 0.1s');
}

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
    Assert::same($e->getMessage(), 'ProcessManager did not receive a wakeup within 1s');
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
Assert::contains($pm->getChildOutput(), 'ProcessManager did not receive a wakeup within 1s');

$pm = new ProcessManager();
$pm->setWaitTimeout(1);
try {
    $pm->wait();
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'ProcessManager did not receive a wakeup within 1s');
}

$pm = new ProcessManager();
$pm->setWaitTimeout(1);
$pm->childFunc = function (): void {
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
try {
    $pm->run();
    Assert::true(false);
} catch (RuntimeException $e) {
    Assert::same($e->getMessage(), 'ProcessManager child exited with code 0 and signal 0 before sending a wakeup');
}
Assert::false(Process::wait(false));

echo "DONE\n";
?>
--EXPECT--
DONE
