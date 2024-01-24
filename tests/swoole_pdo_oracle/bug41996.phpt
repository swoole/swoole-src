--TEST--
swoole_pdo_oracle: PDO OCI Bug #41996 (Problem accessing Oracle ROWID)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
?>
--FILE--
<?php
use function Swoole\Coroutine\run;
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_ORACLE]);
run(function() {
    $db = PdoOracleTest::create();
    $stmt = $db->prepare('SELECT rowid FROM dual');
    $stmt->execute();
    $row = $stmt->fetch();
    var_dump(strlen($row[0]) > 0);
});
?>
--EXPECT--
bool(true)
