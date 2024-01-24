--TEST--
swoole_pdo_sqlite: SQLite variant
--SKIPIF--
<?php
if (PHP_VERSION_ID < 80100) {
    require __DIR__ . '/../include/skipif.inc';
    skip('php version 8.1 or higher');
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

    try {
        var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, NULL));
    } catch (\TypeError $e) {
        echo $e->getMessage(), \PHP_EOL;
    }
    var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, 1));
    try {
        var_dump($pdo->setAttribute(PDO::NULL_TO_STRING, 'nonsense'));
    } catch (\TypeError $e) {
        echo $e->getMessage(), \PHP_EOL;
    }

    @unlink(__DIR__."/foo.db");
});
?>
--EXPECT--
Attribute value must be of type int for selected attribute, null given
bool(true)
Attribute value must be of type int for selected attribute, string given
