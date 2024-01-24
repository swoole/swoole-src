--TEST--
swoole_pdo_sqlite: Testing sqliteCreateFunction() produces warning when
un-callable function passed
--CREDITS--
Chris MacPherson chris@kombine.co.uk
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
    $db = new PDO( 'sqlite::memory:');

    try {
        $db->sqliteCreateFunction('bar-alias', 'bar');
    } catch (\TypeError $e) {
        echo $e->getMessage() . \PHP_EOL;
    }
});
?>
--EXPECT--
PDO::sqliteCreateFunction(): Argument #2 ($callback) must be a valid callback, function "bar" not found or invalid function name
