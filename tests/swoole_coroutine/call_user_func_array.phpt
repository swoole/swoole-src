--TEST--
swoole_coroutine: call_user_func_array
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

class A {
	public function foo() {
		call_user_func_array([$this, "bar"], []);
		echo "foo\n";
	}
	protected function bar() {
		echo "bar\n";
	}
}
$a = new A;
call_user_func_array([$a, "foo"], []);
?>
--EXPECT--
bar
foo
