--TEST--
swoole_coroutine: call_user_func_array
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class A {
	public function foo($params) {
        echo "$params\n";
        call_user_func_array([$this, "bar"], ["bar"]);		
	}
	protected function bar($params) {
        echo "$params\n";
	}
}
$a = new A;
call_user_func_array([$a, "foo"], ["foo"]);
?>
--EXPECT--
foo
bar
