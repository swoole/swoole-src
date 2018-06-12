--TEST--
swoole_lock: trylock

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

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
