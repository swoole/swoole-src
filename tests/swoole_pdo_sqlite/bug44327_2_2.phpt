--TEST--
swoole_pdo_sqlite:queryString property & numeric offsets / Crash)
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80100) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.1 or higher');
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
    $db = new PDO('sqlite::memory:');

    $x = $db->query('select 1 as queryString');
    var_dump($x, $x->queryString);

    $y = $x->fetch();
    var_dump($y, @$y->queryString);

    print "--------------------------------------------\n";

    $x = $db->query('select 1 as queryString');
    var_dump($x, $x->queryString);

    $y = $x->fetch(PDO::FETCH_LAZY);
    var_dump($y, $y->queryString);
});
?>
--EXPECTF--
object(PDOStatement)#%d (1) {
  ["queryString"]=>
  string(23) "select 1 as queryString"
}
string(23) "select 1 as queryString"
array(2) {
  ["queryString"]=>
  int(1)
  [0]=>
  int(1)
}
NULL
--------------------------------------------
object(PDOStatement)#%d (1) {
  ["queryString"]=>
  string(23) "select 1 as queryString"
}
string(23) "select 1 as queryString"
object(PDORow)#%d (1) {
  ["queryString"]=>
  string(23) "select 1 as queryString"
}
string(23) "select 1 as queryString"
