--TEST--
swoole_pdo_sqlite: Testing open flags
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
    $filename = __DIR__ . DIRECTORY_SEPARATOR . "pdo_sqlite_open_flags.db";

    // Default open flag is read-write|create
    $db = new PDO('sqlite:' . $filename, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    var_dump($db->exec('CREATE TABLE test1 (id INT);'));

    $db = new PDO('sqlite:' . $filename, null, null, [PDO::SQLITE_ATTR_OPEN_FLAGS => PDO::SQLITE_OPEN_READONLY, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

    var_dump($db->exec('CREATE TABLE test2 (id INT);'));

    $db->exec('drop table test1');
    $db->exec('drop table test2');
});
?>
--CLEAN--
<?php
$filename = __DIR__ . DIRECTORY_SEPARATOR . "pdo_sqlite_open_flags.db";
if (file_exists($filename)) {
    unlink($filename);
}
?>
--EXPECTF--
int(0)

Fatal error: Uncaught PDOException: SQLSTATE[HY000]: General error: 8 attempt to write a readonly database in %s
Stack trace:
%s
%A
  thrown in %s
