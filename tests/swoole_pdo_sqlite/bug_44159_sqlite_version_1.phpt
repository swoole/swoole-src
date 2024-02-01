--TEST--
swoole_pdo_sqlite: SQLite variant
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
    $pdo = new PDO("sqlite:".__DIR__."/foo.db");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_WARNING);

    var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, NULL));
    var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, 1));
    var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, 'nonsense'));

    @unlink(__DIR__."/foo.db");
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
