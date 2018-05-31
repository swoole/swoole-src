--TEST--
swoole_lock: mutex

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
    echo "[Parent] exit\n";
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
[Child] Wait Lock
[Parent] exit
[Child] Get Lock
[Child] exit
