--TEST--
swoole_pdo_sqlite: Bug #50728 (All PDOExceptions hardcode 'code' property to 0)
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
    try {
        $a = new PDO("sqlite:/this/path/should/not/exist.db");
    } catch (PDOException $e) {
        var_dump($e->getCode());
    }
});
?>
--EXPECT--
int(14)
