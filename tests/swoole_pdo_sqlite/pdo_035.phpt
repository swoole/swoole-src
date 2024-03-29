--TEST--
swoole_pdo_sqlite: PDORow + get_parent_class()
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
    $db->exec('CREATE TABLE test (id int)');
    $db->exec('INSERT INTO test VALUES (23)');

    $stmt = $db->prepare('SELECT id FROM test');
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_LAZY);

    echo get_class($result), "\n";
    var_dump(get_parent_class($result));

    try {
        $result->foo = 1;
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
    try {
        $result[0] = 1;
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
    try {
        unset($result->foo);
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
    try {
        unset($result[0]);
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
});
?>
--EXPECT--
PDORow
bool(false)
Cannot write to PDORow property
Cannot write to PDORow offset
Cannot unset PDORow property
Cannot unset PDORow offset
