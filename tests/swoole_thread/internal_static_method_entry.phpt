--TEST--
swoole_thread: internal static method entries and arguments
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach (['DateTimeImmutable::createFromFormat', '\\dAtEtImEiMmUtAbLe::CrEaTeFrOmFoRmAt'] as $entry) {
    $thread = new Swoole\Thread($entry, '!Y-m-d', '2026-11-23');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    if (PHP_VERSION_ID >= 80400) {
        Assert::isInstanceOf($thread->getResult(), DateTimeImmutable::class);
        Assert::same($thread->getResult()->format('Y-m-d'), '2026-11-23');
    } else {
        Assert::null($thread->getResult());
    }
}
$thread = new Swoole\Thread('Swoole\\Thread::getArguments');
Assert::true($thread->join());
Assert::same($thread->getExitStatus(), 0);
Assert::same(Swoole\Thread::activeCount(), 1);
echo "DONE\n";
?>
--EXPECT--
DONE
