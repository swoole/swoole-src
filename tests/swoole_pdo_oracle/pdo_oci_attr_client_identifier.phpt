--TEST--
swoole_pdo_oracle: Setting session client identifier
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
    $query = 'select client_identifier from v$session where sid = sys_context(\'USERENV\', \'SID\')';

    $dbh = PdoOracleTest::create();

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'CLIENT_IDENTIFIER NOT SET: ';
    var_dump($row['client_identifier']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_IDENTIFIER, "some client identifier"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'CLIENT_IDENTIFIER SET: ';
    var_dump($row['client_identifier']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_IDENTIFIER, "something else!"));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'CLIENT_IDENTIFIER RESET: ';
    var_dump($row['client_identifier']);

    var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_IDENTIFIER, null));

    $stmt = $dbh->query($query);
    $row = $stmt->fetch();
    echo 'CLIENT_IDENTIFIER NULLED: ';
    var_dump($row['client_identifier']);

    echo "Done\n";
});
?>
--EXPECT--
CLIENT_IDENTIFIER NOT SET: NULL
bool(true)
CLIENT_IDENTIFIER SET: string(22) "some client identifier"
bool(true)
CLIENT_IDENTIFIER RESET: string(15) "something else!"
bool(true)
CLIENT_IDENTIFIER NULLED: NULL
Done
