--TEST--
swoole_pdo_sqlite: Testing invalid callback for sqliteCreateAggregate()
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
    $pdo = new PDO('sqlite::memory:');

    try {
        $pdo->sqliteCreateAggregate('foo', 'a', '');
    } catch (\TypeError $e) {
        echo $e->getMessage() . \PHP_EOL;
    }
    try {
        $pdo->sqliteCreateAggregate('foo', 'strlen', '');
    } catch (\TypeError $e) {
        echo $e->getMessage() . \PHP_EOL;
    }
});
?>
--EXPECT--
PDO::sqliteCreateAggregate(): Argument #2 ($step) must be a valid callback, function "a" not found or invalid function name
PDO::sqliteCreateAggregate(): Argument #3 ($finalize) must be a valid callback, function "" not found or invalid function name
