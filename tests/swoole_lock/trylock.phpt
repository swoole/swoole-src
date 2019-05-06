--TEST--
swoole_lock: trylock
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Lock;

$lock = new Lock(LOCK::MUTEX);
Assert::assert($lock->lock());

if (pcntl_fork() > 0)
{
    sleep(1);
    Assert::assert($lock->unlock());
    Assert::assert($lock->lock());
    pcntl_wait($status);
}
else
{
    Assert::false($lock->trylock());
    Assert::assert($lock->unlock());
}
?>
--EXPECT--
