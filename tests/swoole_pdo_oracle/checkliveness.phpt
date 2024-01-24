--TEST--
swoole_pdo_oracle: PDO OCI checkliveness (code coverage)
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
    try {
        $db = new PDO(ORACLE_TNS, ORACLE_USER, ORACLE_PASSWORD, array(PDO::ATTR_PERSISTENT => true));
    }
    catch (PDOException $e) {
        echo 'Connection failed: ' . $e->getMessage();
        exit;
    }

    // This triggers the call to check liveness
    try {
        $db = new PDO(ORACLE_TNS, ORACLE_USER, ORACLE_PASSWORD, array(PDO::ATTR_PERSISTENT => true));
    }
    catch (PDOException $e) {
        echo 'Connection failed: ' . $e->getMessage();
        exit;
    }

    $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

    try {
        $stmt = $db->prepare('SELECT * FROM dual');
        $stmt->execute();
        $row = $stmt->fetch();
        var_dump($row);
    } catch (PDOException $e) {
        print $e->getMessage();
    }

    $db = null;
});
?>
--EXPECT--
array(2) {
  ["DUMMY"]=>
  string(1) "X"
  [0]=>
  string(1) "X"
}
