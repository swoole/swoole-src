--TEST--
swoole_pdo_sqlite: PDO SQLite Bug #78192 SegFault when reuse statement after schema change
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
    $connection = new \PDO('sqlite::memory:');
    $connection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    $connection->query('CREATE TABLE user (id INTEGER PRIMARY KEY NOT NULL, name VARCHAR(255) NOT NULL)');

    $stmt = $connection->prepare('INSERT INTO user (id, name) VALUES(:id, :name)');
    $stmt->execute([
        'id'   => 10,
        'name' => 'test',
    ]);

    $stmt = $connection->prepare('SELECT * FROM user WHERE id = :id');
    $stmt->execute(['id' => 10]);
    var_dump($stmt->fetchAll(\PDO::FETCH_ASSOC));

    $connection->query('ALTER TABLE user ADD new_col VARCHAR(255)');
    $stmt->execute(['id' => 10]);
    var_dump($stmt->fetchAll(\PDO::FETCH_ASSOC));
});
?>
--EXPECT--
array(1) {
  [0]=>
  array(2) {
    ["id"]=>
    string(2) "10"
    ["name"]=>
    string(4) "test"
  }
}
array(1) {
  [0]=>
  array(3) {
    ["id"]=>
    string(2) "10"
    ["name"]=>
    string(4) "test"
    ["new_col"]=>
    NULL
  }
}
