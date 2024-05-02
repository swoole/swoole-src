--TEST--
swoole_pdo_sqlite: Testing sqliteCreateAggregate()
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

    $db->query('CREATE TABLE IF NOT EXISTS foobar (id INT AUTO INCREMENT, name TEXT)');

    $db->query('INSERT INTO foobar VALUES (NULL, "PHP")');
    $db->query('INSERT INTO foobar VALUES (NULL, "PHP6")');

    $db->sqliteCreateAggregate('testing', function(&$a, $b) { $a .= $b; return $a; }, function(&$v) { return $v; });

    foreach ($db->query('SELECT testing(name) FROM foobar') as $row) {
        var_dump($row);
    }

    $db->query('DROP TABLE foobar');
});
?>
--EXPECT--
array(2) {
  ["testing(name)"]=>
  string(2) "12"
  [0]=>
  string(2) "12"
}
