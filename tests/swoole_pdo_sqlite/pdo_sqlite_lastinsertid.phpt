--TEST--
swoole_pdo_sqlite: Testing lastInsertId()
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
Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO('sqlite::memory:');
    $db->query('CREATE TABLE IF NOT EXISTS foo (id INT AUTO INCREMENT, name TEXT)');
    $db->query('INSERT INTO foo VALUES (NULL, "PHP")');
    $db->query('INSERT INTO foo VALUES (NULL, "PHP6")');
    var_dump($db->query('SELECT * FROM foo'));
    var_dump($db->errorInfo());
    var_dump($db->lastInsertId());

    $db->query('DROP TABLE foo');
});
?>
--EXPECTF--
object(PDOStatement)#%d (1) {
  ["queryString"]=>
  string(17) "SELECT * FROM foo"
}
array(3) {
  [0]=>
  string(5) "00000"
  [1]=>
  NULL
  [2]=>
  NULL
}
string(1) "2"
