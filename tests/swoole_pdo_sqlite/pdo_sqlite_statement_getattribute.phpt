--TEST--
swoole_pdo_sqlite:getAttribute()
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

    $st = $db->prepare('SELECT 1;');

    $const = PHP_VERSION_ID >= 80500 ? PDO\SQLITE::ATTR_READONLY_STATEMENT: PDO::SQLITE_ATTR_READONLY_STATEMENT;

    var_dump($st->getAttribute($const));

    $st = $db->prepare('CREATE TABLE test (a TEXT);');

    var_dump($st->getAttribute($const));
});
?>
--EXPECT--
bool(true)
bool(false)
