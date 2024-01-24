--TEST--
swoole_pdo_sqlite: GC support for PDO Sqlite driver data
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
class Obj {
	public $a;
	public function callback() { }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $obj = new Obj;
    $obj->a = new PDO('sqlite::memory:');
    $obj->a->sqliteCreateFunction('func1', function() use ($obj) {}, 1);
    $obj->a->sqliteCreateAggregate('func2', function() use ($obj) {}, function() use($obj) {});
    $obj->a->sqliteCreateCollation('col', function() use ($obj) {});
});
?>
===DONE===
--EXPECT--
===DONE===
