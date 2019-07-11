--TEST--
swoole_process: deamon
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function(\swoole_process $proc) {
    $r = \swoole_process::daemon();
    Assert::assert($r);

    $proc->push(posix_getpid());
});
$proc->useQueue();
$forkPid = $proc->start();
$demonPid = intval($proc->pop());

Assert::assert($forkPid !== $demonPid);

\swoole_process::kill($demonPid, SIGKILL);

\swoole_process::wait(true);
\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
