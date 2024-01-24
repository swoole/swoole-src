--TEST--
swoole_pdo_oracle: Set prefetch on connection
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
    echo "Test connect\n";
    $dbh->setAttribute(PDO::ATTR_PREFETCH, 101);

    echo $dbh->getAttribute(PDO::ATTR_PREFETCH), "\n";

    // Verify can fetch
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Test set 102\n";
    $dbh->setAttribute(PDO::ATTR_PREFETCH, 102);
    echo $dbh->getAttribute(PDO::ATTR_PREFETCH), "\n";

    // Verify can fetch
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Test set -1: (Uses 0)\n";
    $dbh->setAttribute(PDO::ATTR_PREFETCH, -1);
    echo $dbh->getAttribute(PDO::ATTR_PREFETCH), "\n";

    // Verify can fetch
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Test set PHP_INT_MAX: (Uses default)\n";
    $dbh->setAttribute(PDO::ATTR_PREFETCH, PHP_INT_MAX);
    echo $dbh->getAttribute(PDO::ATTR_PREFETCH), "\n";

    // Verify can fetch
    $s = $dbh->prepare("select dummy from dual" );
    $s->execute();
    while ($r = $s->fetch()) {
        echo $r[0] . "\n";
    }

    echo "Done\n";
});
?>
--EXPECT--
Test connect
101
X
Test set 102
102
X
Test set -1: (Uses 0)
0
X
Test set PHP_INT_MAX: (Uses default)
100
X
Done
