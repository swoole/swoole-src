--TEST--
Test of swoole_process exec
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
$process = new swoole_process('python_process', true);
$pid = $process->start();

function python_process(swoole_process $worker)
{
    $worker->exec('/usr/bin/python', array(__DIR__ . "/echo.py"));
}

$process->write("Hello World\n");
echo $process->read();
?>
Done
--EXPECTREGEX--
Python: Hello World
Done.*
--CLEAN--
