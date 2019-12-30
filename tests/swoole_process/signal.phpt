--TEST--
swoole_process: signal
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

//父进程中先设置信号
Process::signal(SIGCHLD, function ()
{
    Process::signal(SIGCHLD, null);
    Process::signal(SIGTERM, null);
    Swoole\Event::del(STDIN);
    Swoole\Timer::clearAll();
    echo "PARENT WAIT\n";
});

//测试被子进程覆盖信号
Process::signal(SIGTERM, function () {
    //释放信号，否则底层会报内存泄漏
    Process::signal(SIGTERM, null);
    echo "PARENT SIGTERM\n";
    Swoole\Event::exit();
});

$pid = (new Process(function ()
{
    Process::signal(SIGTERM, function ($sig) {
        echo "CHILD SIGTERM\n";
        Process::signal(SIGTERM, function ($sig) {
            echo "CHILD EXIT\n";
            Swoole\Event::del(STDIN);
        });
    });

    //never calback
    Swoole\Event::add(STDIN, function () {});

}))->start();

Swoole\Timer::after(500, function() use ($pid) {
    Process::kill($pid, SIGTERM);
    Swoole\Timer::after(500, function() use ($pid) {
        Process::kill($pid, SIGTERM);
    });
});

//never calback
Swoole\Event::add(STDIN, function ($fp) {
    echo fread($fp, 8192);
});

Swoole\Event::wait();
?>
--EXPECT--
CHILD SIGTERM
CHILD EXIT
PARENT WAIT
