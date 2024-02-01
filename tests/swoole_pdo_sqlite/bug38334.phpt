--TEST--
swoole_pdo_sqlite: Proper data-type support for PDO_SQLITE
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
    $db->exec('CREATE TABLE test (i INTEGER , f DOUBLE, s VARCHAR(255))');
    $db->exec('INSERT INTO test VALUES (42, 46.7, "test")');
    var_dump($db->query('SELECT * FROM test')->fetch(PDO::FETCH_ASSOC));

    // Check handling of integers larger than 32-bit.
    $db->exec('INSERT INTO test VALUES (10000000000, 0.0, "")');
    $i = $db->query('SELECT i FROM test WHERE f = 0.0')->fetchColumn(0);
    if (PHP_INT_SIZE >= 8) {
        var_dump($i === 10000000000);
    } else {
        var_dump($i === '10000000000');
    }

    // Check storing of strings into integer/float columns.
    $db->exec('INSERT INTO test VALUES ("test", "test", "x")');
    var_dump($db->query('SELECT * FROM test WHERE s = "x"')->fetch(PDO::FETCH_ASSOC));
});
?>
--EXPECT--
array(3) {
  ["i"]=>
  int(42)
  ["f"]=>
  float(46.7)
  ["s"]=>
  string(4) "test"
}
bool(true)
array(3) {
  ["i"]=>
  string(4) "test"
  ["f"]=>
  string(4) "test"
  ["s"]=>
  string(1) "x"
}
