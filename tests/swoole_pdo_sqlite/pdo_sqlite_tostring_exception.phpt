--TEST--
swoole_pdo_sqlite: __toString() exception during PDO Sqlite parameter binding
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
class throws {
    function __toString() {
        throw new Exception("Sorry");
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $db = new PDO('sqlite::memory:');
    $db->exec('CREATE TABLE t(id int, v varchar(255))');

    $stmt = $db->prepare('INSERT INTO t VALUES(:i, :v)');
    $param1 = 1234;
    $stmt->bindValue('i', $param1);
    $param2 = "foo";
    $stmt->bindParam('v', $param2);

    $param2 = new throws;

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo "Exception thrown ...\n";
    }

    try {
        $stmt->execute();
    } catch (Exception $e) {
        echo "Exception thrown ...\n";
    }

    $query = $db->query("SELECT * FROM t");
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        print_r($row);
    }
});
?>
--EXPECT--
Exception thrown ...
Exception thrown ...
