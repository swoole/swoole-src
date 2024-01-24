--TEST--
swoole_pdo_sqlite: Bug #47769 (Strange extends PDO)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
class test extends PDO
{
    protected function isProtected() {
        echo "this is a protected method.\n";
    }
    private function isPrivate() {
        echo "this is a private method.\n";
    }

    public function quote($str, $paramtype = NULL): string|false {
        $this->isProtected();
        $this->isPrivate();
        print $str ."\n";

        return $str;
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $test = new test('sqlite::memory:');
    $test->quote('foo');
    $test->isProtected();
});
?>
--EXPECTF--
this is a protected method.
this is a private method.
foo

Fatal error: Uncaught Error: Call to protected method test::isProtected() from global scope in %s:%d
Stack trace:
%A
  thrown in %s on line %d
