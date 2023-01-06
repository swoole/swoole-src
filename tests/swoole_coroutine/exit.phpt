--TEST--
swoole_coroutine: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/exit.php';
?>
--EXPECTF--
NULL
NULL
bool(true)
bool(false)
int(1)
float(1.1)
string(4) "exit"
array(1) {
  ["exit"]=>
  string(2) "ok"
}
object(stdClass)#%d (%d) {
  ["exit"]=>
  string(2) "ok"
}
resource(%d) of type (stream)
int(0)
