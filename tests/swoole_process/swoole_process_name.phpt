--TEST--
swoole_process: name
--SKIPIF--
<?php
require __DIR__ . "/../include/skipif.inc";
require __DIR__ . "/../inc/skipifDarwin.inc";
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

$name = "SWOOLE_PROCESS_TEST_" . rand(1, 100);

$proc = new \swoole_process(function($childProc) { 
	global $name;
	$childProc->name($name);
	sleep(PHP_INT_MAX); 
});

$pid = $proc->start();
$count = trim(`ps aux|grep $name|grep -v grep|wc -l`);
assert($count == 1);
\swoole_process::kill($pid, SIGKILL);

\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS