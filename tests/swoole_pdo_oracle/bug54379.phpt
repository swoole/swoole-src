--TEST--
swoole_pdo_oracle: UTF-8 output gets truncated)
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
    try {
            $db->exec("DROP TABLE test");
    } catch (Exception $e) {
    }
    $db->exec("CREATE TABLE test (col1 NVARCHAR2(20))");
    $db->exec("INSERT INTO test VALUES('12345678901234567890')");
    $db->exec("INSERT INTO test VALUES('あいうえおかきくけこさしすせそたちつてと')");
    $stmt = $db->prepare("SELECT * FROM test");
    $stmt->execute();
    var_dump($stmt->fetchAll(PDO::FETCH_ASSOC));
    $db->exec("DROP TABLE test");
});
?>
--EXPECT--
array(2) {
  [0]=>
  array(1) {
    ["col1"]=>
    string(20) "12345678901234567890"
  }
  [1]=>
  array(1) {
    ["col1"]=>
    string(60) "あいうえおかきくけこさしすせそたちつてと"
  }
}
