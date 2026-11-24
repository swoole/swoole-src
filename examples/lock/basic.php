<?php
// Swoole\Lock guards a critical section shared between processes.
// Run: php examples/lock/basic.php
$lock = new Swoole\Lock(SWOOLE_MUTEX);
$lock->lock();
echo 'inside the critical section' . PHP_EOL;
$lock->unlock();
echo 'lock released' . PHP_EOL;
