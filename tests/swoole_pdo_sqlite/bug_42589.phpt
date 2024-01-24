--TEST--
swoole_pdo_sqlite: PDO SQLite Feature Request #42589 (getColumnMeta() should also return table name)
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
    $db = new PDO("sqlite::memory:");

    $db->exec('CREATE TABLE test (field1 VARCHAR(10))');
    $db->exec('INSERT INTO test VALUES("test")');

    $result = $db->query('SELECT * FROM test t1 LEFT JOIN test t2 ON t1.field1 = t2.field1');
    $meta1 = $result->getColumnMeta(0);
    $meta2 = $result->getColumnMeta(1);

    var_dump(!empty($meta1['table']) && $meta1['table'] == 'test');
    var_dump(!empty($meta2['table']) && $meta2['table'] == 'test');
});
?>
--EXPECT--
bool(true)
bool(true)
