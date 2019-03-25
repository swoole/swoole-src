--TEST--
swoole_lock: trylock
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Lock;

$lock = new Lock(LOCK::MUTEX);
assert($lock->lock());

if (pcntl_fork() > 0)
{
    sleep(1);
    assert($lock->unlock());
    assert($lock->lock());
    pcntl_wait($status);
}
else
{
    assert($lock->trylock() == false);
    assert($lock->unlock());
}
?>
--EXPECT--
