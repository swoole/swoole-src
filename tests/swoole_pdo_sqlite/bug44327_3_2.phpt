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

    $x = $db->query('select 1 as queryStringxx');
    $y = $x->fetch(PDO::FETCH_LAZY);
    var_dump($y, $y->queryString, $y->queryStringzz, $y->queryStringxx);

    print "---\n";

    var_dump($y[5], $y->{3});
});
?>
--EXPECTF--
object(PDORow)#%d (2) {
  ["queryString"]=>
  string(25) "select 1 as queryStringxx"
  ["queryStringxx"]=>
  int(1)
}
string(25) "select 1 as queryStringxx"
NULL
int(1)
---
NULL
NULL
