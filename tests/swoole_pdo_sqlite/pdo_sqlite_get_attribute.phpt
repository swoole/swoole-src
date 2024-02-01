--TEST--
swoole_pdo_sqlite: Testing getAttribute()
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
    var_dump($pdo->getAttribute(PDO::ATTR_SERVER_VERSION));
    var_dump($pdo->getAttribute(PDO::ATTR_CLIENT_VERSION));
});
?>
--EXPECTF--
string(%d) "%s"
string(%d) "%s"
