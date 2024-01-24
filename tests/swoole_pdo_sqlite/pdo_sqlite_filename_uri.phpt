--TEST--
swoole_pdo_sqlite: Testing filename uri
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
    // create with default read-write|create mode
    $filename = "file:" . __DIR__ . DIRECTORY_SEPARATOR . "pdo_sqlite_filename_uri.db";

    $db = new PDO('sqlite:' . $filename);

    var_dump($db->exec('CREATE TABLE test1 (id INT);'));

    // create with readonly mode
    $filename = "file:" . __DIR__ . DIRECTORY_SEPARATOR . "pdo_sqlite_filename_uri.db?mode=ro";

    $db = new PDO('sqlite:' . $filename);

    var_dump($db->exec('CREATE TABLE test2 (id INT);'));
});
?>
--CLEAN--
<?php
$filename = __DIR__ . DIRECTORY_SEPARATOR . "pdo_sqlite_filename_uri.db";
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
