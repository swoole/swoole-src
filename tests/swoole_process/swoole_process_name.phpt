--TEST--
swoole_process: name
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_darwin();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$name = "SWOOLE_PROCESS_TEST_" . rand(1, 100);

$proc = new Swoole\Process(function ($childProc) {
    global $name;
    $childProc->name($name);
    sleep(PHP_INT_MAX);
});

$pid = $proc->start();
$count = (int)trim(`ps aux|grep $name|grep -v grep|wc -l`);
Assert::same($count, 1);
\Swoole\Process::kill($pid, SIGKILL);

\Swoole\Process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
