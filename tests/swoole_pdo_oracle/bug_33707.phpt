--TEST--
PDO OCI Bug #33707 (Errors in select statements not reported)
--SKIPIF--
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
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
    $rs = $db->query('select blah from a_table_that_does_not_exist');
    var_dump($rs);
    var_dump($db->errorInfo());
});
?>
--EXPECTF--
bool(false)
array(3) {
  [0]=>
  string(5) "HY000"
  [1]=>
  int(942)
  [2]=>
  string(%d) "OCIStmtExecute: ORA-00942: table or view does not exist
 (%s:%d)"
}
