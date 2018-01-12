--TEST--
swoole_coroutine: call_user_func_array
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
class A {
	public function foo() {
		Swoole\Coroutine::call_user_func_array([$this, "bar"], []);
		echo "foo\n";
	}
	protected function bar() {
		echo "bar\n";
	}
}
$a = new A;
Swoole\Coroutine::call_user_func_array([$a, "foo"], []);
?>
--EXPECT--
bar
foo
