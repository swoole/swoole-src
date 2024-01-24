--TEST--
swoole_pdo_sqlite: PDO SQLite Bug #33841 (rowCount() does not work on prepared statements)
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
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_sqlite.inc';

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = PdoSqliteTest::create();

    $db->exec('CREATE TABLE test (text)');

    $stmt = $db->prepare("INSERT INTO test VALUES ( :text )");
    $stmt->bindParam(':text', $name);
    $name = 'test1';
    var_dump($stmt->execute(), $stmt->rowCount());

    $stmt = $db->prepare("UPDATE test SET text = :text ");
    $stmt->bindParam(':text', $name);
    $name = 'test2';
    var_dump($stmt->execute(), $stmt->rowCount());
});
?>
--EXPECT--
bool(true)
int(1)
bool(true)
int(1)
