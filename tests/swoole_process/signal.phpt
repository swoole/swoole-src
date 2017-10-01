--TEST--
swoole_process: signal
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

//父进程中先设置信号
swoole_process::signal(SIGCHLD, function ()
{
    swoole_process::signal(SIGCHLD, null);
    swoole_process::signal(SIGTERM, null);
    echo "PARENT WAIT\n";
    swoole_event_exit();
});

//测试被子进程覆盖信号
swoole_process::signal(SIGTERM, function () {
    //释放信号，否则底层会报内存泄漏
    swoole_process::signal(SIGTERM, null);
    echo "PARENT SIGTERM\n";
    swoole_event_exit();
});


$pid = (new \swoole_process(function ()
{
    swoole_process::signal(SIGTERM, function ($sig) {
        echo "CHILD SIGTERM\n";
        swoole_process::signal(SIGTERM, function ($sig) {
            echo "CHILD EXIT\n";
            swoole_event_exit();
        });
    });
}))->start();

swoole_timer_after(500, function() use ($pid) {
    swoole_process::kill($pid, SIGTERM);
    swoole_timer_after(500, function() use ($pid) {
        swoole_process::kill($pid, SIGTERM);
    });
});
swoole_event_wait();
?>
--EXPECT--
CHILD SIGTERM
CHILD EXIT
PARENT WAIT

