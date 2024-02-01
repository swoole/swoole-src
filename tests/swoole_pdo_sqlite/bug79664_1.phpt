--TEST--
swoole_pdo_sqlite:getColumnMeta fails on empty result set)
--SKIPIF--
<?php
if (PHP_VERSION_ID >= 80100) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.0 or lower');
}

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
  ["flags"]=>
  array(0) {
  }
  ["name"]=>
  string(1) "1"
  ["len"]=>
  int(-1)
  ["precision"]=>
  int(0)
  ["pdo_type"]=>
  int(2)
}
