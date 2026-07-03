--TEST--
swoole_thread: Affinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Thread;

$tm = new \SwooleTest\ThreadManager();

$selectCpu = static function (array $cpus, bool $preferLast = false): array {
    Assert::notEmpty($cpus);
    return [$preferLast ? $cpus[array_key_last($cpus)] : $cpus[array_key_first($cpus)]];
};

$tm->parentFunc = function () {
    $thread = new Thread(__FILE__, 'child');
    $r = Thread::getAffinity();
    Assert::notEmpty($r);
    $cpu = $GLOBALS['selectCpu']($r, true);
    Assert::assert(Thread::setAffinity($cpu));
    Assert::eq(Thread::getAffinity(), $cpu);
    $thread->join();
};

$tm->childFunc = function () {
    $r = Thread::getAffinity();
    Assert::notEmpty($r);
    $cpu = $GLOBALS['selectCpu']($r);
    Assert::assert(Thread::setAffinity($cpu));
    Assert::eq(Thread::getAffinity(), $cpu);
};

$tm->run();
?>
--EXPECTF--
