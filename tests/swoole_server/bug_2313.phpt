--TEST--
swoole_server: bug Github#2313
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$serv = new swoole_server("0.0.0.0",9501);
$proc = new swoole_process(function(){});
$serv->addProcess($proc);
if(!is_null($proc->id)){
	echo "SUCCESS";
}
?>
--EXPECT--
SUCCESS