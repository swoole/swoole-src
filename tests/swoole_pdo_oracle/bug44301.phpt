--TEST--
swoole_pdo_oracle: PDO OCI Bug #44301 (Segfault when an exception is thrown on persistent connections)
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
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_PERSISTENT, true);
    try {
        $stmt = $db->prepare('SELECT * FROM no_table');
        $stmt->execute();
    } catch (PDOException $e) {
        print $e->getMessage();
    }
    $db = null;
});
?>
--EXPECTF--
SQLSTATE[HY000]: General error: 942 OCIStmtExecute: ORA-00942: table or view "SYSTEM"."NO_TABLE" does not exist
Help: %s
 (%s:%d)
