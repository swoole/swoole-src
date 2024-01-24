--TEST--
swoole_pdo_sqlite: Bug #70221 (persistent sqlite connection + custom function segfaults)
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
    $dbfile = __DIR__ . '/test.sqlite';
    $db = new PDO('sqlite:'.$dbfile, null, null, array(PDO::ATTR_PERSISTENT => true));
    function _test() { return 42; }
    $db->sqliteCreateFunction('test', '_test', 0);
    print("Everything is fine, no exceptions here\n");
    unset($db);
});
?>
--CLEAN--
<?php
$dbfile = __DIR__ . '/test.sqlite';
unlink($dbfile);
?>
--EXPECT--
Everything is fine, no exceptions here
