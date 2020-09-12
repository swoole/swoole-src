--TEST--
swoole_lock: mutex robust
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip("no supports");
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$file = __DIR__.'/tmp.log';
$fp = fopen($file, 'w+');
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $fp) {
    $lock = new Swoole\Lock(SWOOLE_MUTEX);
    $pid = posix_getpid();
    fwrite($fp, "[Master {$pid}]create lock\n");
    $lock->lock();
    $n = 2;
    while ($n--) {
        $process = new Swoole\Process(function ($p) use ($lock, $fp) {
            fwrite($fp, "[Child {$p->pid}] Wait Lock\n");
            $lock->lock();
            fwrite($fp, "[Child {$p->pid}] Get Lock\n");
            $lock->unlock();
            fwrite($fp, "[Child {$p->pid}] exit\n");
        });
        $process->start();
    }
    sleep(30);
    $lock->unlock();
};

$pm->childFirst();
$pm->run();
fclose($fp);
echo file_get_contents($file);
unlink($file);
?>
--EXPECTF--
[Master %d]create lock
[Child %d] Wait Lock
[Child %d] Wait Lock
[Child %d] Get Lock
[Child %d] exit
[Child %d] Get Lock
[Child %d] exit
