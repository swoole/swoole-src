--TEST--
swoole_pdo_oracle: Setting and using call timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
if (getenv('SKIP_SLOW_TESTS')) die('skip slow tests excluded by request');
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';
PdoOracleTest::skip();
if (strcasecmp(getenv('PDOTEST_USER'), "system") && strcasecmp(getenv('PDOTEST_USER'), "sys")) {
    die("skip needs to be run as a user with access to DBMS_LOCK");
}

$dbh = PdoOracleTest::create();
preg_match('/^[[:digit:]]+/', $dbh->getAttribute(PDO::ATTR_CLIENT_VERSION), $matches);
if (!(isset($matches[0]) && $matches[0] >= 18)) {
    die("skip works only with Oracle 18c or greater version of Oracle client libraries");
}

?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/pdo_oracle.inc';

function mysleep($dbh, $t)
{
    $stmt = $dbh->prepare("begin dbms_lock.sleep(:t); end;");

    if (!$stmt) {
        $error = $dbh->errorInfo();
        echo "Prepare error was ", $error[2], "\n";
        return;
    }
    $stmt->bindParam(":t", $t, PDO::PARAM_INT);

    $r = $stmt->execute();
    if ($r) {
        echo "Execute succeeded\n";
    } else {
        $error = $dbh->errorInfo();
        echo "Execute error was ", $error[2], "\n";
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_ORACLE]);
run(function() {
    $dbh = PdoOracleTest::create();
    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);

    echo "Test 1\n";

    $dbh->setAttribute(PDO::OCI_ATTR_CALL_TIMEOUT, 4000); // milliseconds

    echo "call timeout:\n";
    var_dump($dbh->getAttribute(PDO::OCI_ATTR_CALL_TIMEOUT));

    $r = mysleep($dbh, 8); // seconds
});
?>
===DONE===
<?php exit(0); ?>
--EXPECTF--
Test 1
call timeout:
int(4000)
Execute error was OCIStmtExecute: ORA-%r(03136|03156)%r: %s
 (%s:%d)
===DONE===
