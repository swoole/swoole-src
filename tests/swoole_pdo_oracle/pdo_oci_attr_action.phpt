--TEST--
swoole_pdo_oracle: Setting session action
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
    $dbh = PdoOracleTest::create();
    $query = 'select action from v$session where sid = sys_context(\'USERENV\', \'SID\')';
    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'ACTION NOT SET: ';
    var_dump($row['action']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_ACTION, "some action"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'ACTION SET: ';
    var_dump($row['action']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_ACTION, "something else!"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'ACTION RESET: ';
    var_dump($row['action']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_ACTION, null));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'ACTION NULLED: ';
    var_dump($row['action']);

    echo "Done\n";
});
?>
--EXPECT--
ACTION NOT SET: NULL
bool(true)
ACTION SET: string(11) "some action"
bool(true)
ACTION RESET: string(15) "something else!"
bool(true)
ACTION NULLED: NULL
Done
