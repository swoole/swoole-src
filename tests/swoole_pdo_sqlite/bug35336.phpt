--TEST--
swoole_pdo_sqlite:FETCH_CLASS + __set())
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

class EEE {
    function __set ($field, $value) {
        echo "hello world\n";
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_SQLITE]);
run(function() {
    $a = new PDO("sqlite::memory:");// pool ("sqlite::memory:");
    $a->query ("CREATE TABLE test (a integer primary key, b text)");
    $b = $a->prepare("insert into test (b) values (?)");
    $b->execute(array (5));
    $rez = $a->query ("SELECT * FROM test")->fetchAll(PDO::FETCH_CLASS, 'EEE');

    echo "Done\n";
});
?>
--EXPECT--
hello world
hello world
Done
