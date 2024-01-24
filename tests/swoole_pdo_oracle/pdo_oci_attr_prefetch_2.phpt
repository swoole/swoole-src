--TEST--
swoole_pdo_oracle: prefetch on statements
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
    $s = $dbh->prepare("select '' as myempty, null as mynull from dual", array(PDO::ATTR_PREFETCH => 101));

    echo "Test 1: Can't set prefetch after prepare\n";
    var_dump($s->setAttribute(PDO::ATTR_PREFETCH, 102));

    // Verify can fetch
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Test 2: Turn off prefetching\n";
    $s = $dbh->prepare("select '' as myempty, null as mynull from dual", array(PDO::ATTR_PREFETCH => 0));
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Done\n";
});
?>
--EXPECTF--
Test 1: Can't set prefetch after prepare

Fatal error: Uncaught PDOException: SQLSTATE[IM001]: Driver does not support this function: This driver doesn't support setting attributes in %s:%d
Stack trace:
#0 %s(%d): PDOStatement->setAttribute(1, 102)
%A
  thrown in %s on line %d
