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

Assert::eq(Thread::API_NAME, PHP_OS_FAMILY === 'Windows' ? 'Windows Threads' : 'POSIX Threads');

$selectCpu = static function (array $cpus, bool $last = false): array {
    Assert::notEmpty($cpus);
    return [$last ? $cpus[array_key_last($cpus)] : $cpus[array_key_first($cpus)]];
};

$tm->parentFunc = function () use ($selectCpu) {
    $thread = new Thread(__FILE__, 'child');
    $r = Thread::getAffinity();
    $cpu = $selectCpu($r, true);
    Assert::assert(Thread::setAffinity($cpu));
    Assert::eq(Thread::getAffinity(), $cpu);
    $thread->join();
};

$tm->childFunc = function () use ($selectCpu) {
    $r = Thread::getAffinity();
    $cpu = $selectCpu($r);
    Assert::assert(Thread::setAffinity($cpu));
    Assert::eq(Thread::getAffinity(), $cpu);
};

$tm->run();
?>
--EXPECTF--
