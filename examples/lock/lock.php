<?php
/**
 * SWOOLE_MUTEX 互斥锁
 * SWOOLE_FILELOCK 文件锁，需要在第二个参数传入一个锁文件
 * SWOOLE_SPINLOCK 自旋锁(请查看swoole扩展信息，检测是否支持)
 * SWOOLE_SEM 信号量
 * SWOOLE_RWLOCK 读写锁
 */

$lock = new swoole_lock(SWOOLE_MUTEX);
echo "[Master]create lock\n";
$lock->lock();
if (pcntl_fork() > 0)
{
    sleep(1);
    $lock->unlock();
}
else
{
    echo "[Child] Wait Lock\n";
    $lock->lock();
    echo "[Child] Get Lock\n";
    $lock->unlock();
    exit("[Child] exit\n");
}
echo "[Master]release lock\n";
unset($lock);
sleep(1);
echo "[Master]exit\n";

