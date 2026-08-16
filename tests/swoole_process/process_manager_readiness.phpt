--TEST--
swoole_process: ProcessManager readiness modes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\ProcessManager;

$pm            = new ProcessManager();
$pm->childFunc = function () use ($pm): void {
    $pm->wakeup();
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
$pm->run();

$pm            = new ProcessManager();
$pm->childFunc = function (): void {
};
$pm->parentFunc = function () use ($pm): void {
    $pm->wakeup();
};
$pm->parentFirst();
$pm->run();

$pm = new ProcessManager();
$pm->wakeup();
$pm->childFunc = function (): void {
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
$pm->run();

$pm = new ProcessManager();
$pm->setWaitTimeout(0);
$pm->childFunc = function (): void {
};
$pm->parentFunc = function (): void {
};
$pm->childFirst();
$pm->run();

echo "DONE\n";
?>
--EXPECT--
DONE
