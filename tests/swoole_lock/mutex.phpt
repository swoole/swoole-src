--TEST--
swoole_lock: mutex
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$lock = new Swoole\Lock(Swoole\Lock::MUTEX);
echo "[Parent] Lock\n";
assert($lock->lock());

if (pcntl_fork() > 0)
{
    usleep(100 * 1000);
    echo "[Parent] Unlock\n";
    assert($lock->unlock());
    echo "[Parent] Exit\n";
    pcntl_wait($status);
}
else
{
    echo "[Child] Wait Lock\n";
    assert($lock->lock());
    echo "[Child] Get Lock\n";
    assert($lock->unlock());
    exit("[Child] exit\n");
}
?>
--EXPECT--
[Parent] Lock
[Child] Wait Lock
[Parent] Unlock
[Parent] Exit
[Child] Get Lock
[Child] exit
