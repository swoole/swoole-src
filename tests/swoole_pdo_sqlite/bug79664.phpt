--TEST--
Bug #79664 (PDOStatement::getColumnMeta fails on empty result set)
--SKIPIF--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';
PdoSqliteTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $pdo = new PDO('sqlite::memory:', null, null, [
    	PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $stmt = $pdo->query('select 1 where 0');
    if ($stmt->columnCount()) {
        var_dump($stmt->getColumnMeta(0));
    }
});
?>
--EXPECT--
array(6) {
  ["native_type"]=>
  string(4) "null"
  ["pdo_type"]=>
  int(0)
  ["flags"]=>
  array(0) {
  }
  ["name"]=>
  string(1) "1"
  ["len"]=>
  int(-1)
  ["precision"]=>
  int(0)
}
