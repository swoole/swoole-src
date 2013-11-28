<?php
/**
 * SWOOLE_MUTEX 互斥锁
 * SWOOLE_FILELOCK 文件锁，需要在第二个参数传入一个锁文件
 * SWOOLE_SPINLOCK 自旋锁(请查看swoole扩展信息，检测是否支持)
 * SWOOLE_SEM 信号量
 * SWOOLE_RWLOCK 读写锁
 */

$lock = new swoole_lock(SWOOLE_FILELOCK, __DIR__."/lock");
echo "create lock\n";
$abc = 1;
$lock->lock();

echo "get lock\n";
$abc = 100;
sleep(1);
$lock->unlock();
echo "release lock\n";
unset($lock);
sleep(5);
echo "exit\n";

