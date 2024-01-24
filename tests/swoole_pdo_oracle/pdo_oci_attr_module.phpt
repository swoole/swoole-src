--TEST--
swoole_pdo_oracle: Setting session module
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
    $query = 'select module from v$session where sid = sys_context(\'USERENV\', \'SID\')';

    $dbh = PdoOracleTest::create();

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_MODULE, "some module"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'MODULE SET: ';
    var_dump($row['module']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_MODULE, "something else!"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'MODULE RESET: ';
    var_dump($row['module']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_MODULE, null));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'MODULE NULLED: ';
    var_dump($row['module']);

    echo "Done\n";
});
?>
--EXPECT--
bool(true)
MODULE SET: string(11) "some module"
bool(true)
MODULE RESET: string(15) "something else!"
bool(true)
MODULE NULLED: NULL
Done
