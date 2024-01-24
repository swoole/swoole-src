--TEST--
swoole_pdo_oracle: closing a connection in non-autocommit mode commits data
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

    // Check connection can be created with AUTOCOMMIT off
    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_SILENT);
    $dbh->setAttribute(PDO::ATTR_AUTOCOMMIT, false);
    $dbh->exec("drop table pdo_ac_tab");

    $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    print "PDO::ATTR_AUTOCOMMIT: ";
    var_dump($dbh->getAttribute(PDO::ATTR_AUTOCOMMIT));

    echo "Insert data\n";

    $dbh->exec("create table pdo_ac_tab (col1 varchar2(20))");

    $dbh->exec("insert into pdo_ac_tab (col1) values ('some data')");

    $dbh = null; // close first connection

    echo "Second connection should be able to see committed data\n";
    $dbh2 = PdoOracleTest::create();
    $s = $dbh2->prepare("select col1 from pdo_ac_tab");
    $s->execute();
    while ($r = $s->fetch()) {
        echo "Data is: " . $r[0] . "\n";
    }

    $dbh2->exec("drop table pdo_ac_tab");

    echo "Done\n";
});
?>
--EXPECT--
PDO::ATTR_AUTOCOMMIT: bool(false)
Insert data
Second connection should be able to see committed data
Done
