--TEST--
swoole_pdo_oracle: Server version and info
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
    echo "Test 1\n";
    echo "ATTR_SERVER_VERSION: ";
    var_dump($dbh->getAttribute(PDO::ATTR_SERVER_VERSION));

    echo "Test 2\n";
    echo "ATTR_SERVER_INFO\n";
    $si = $dbh->getAttribute(PDO::ATTR_SERVER_INFO);
    $pos = strpos($si, "Oracle");
    if ($pos === 0) {
        echo "Found 'Oracle' at position $pos as expected\n";
    } else {
        echo "Unexpected result.  Server info was:\n";
        var_dump($si);
    }

    echo "Done\n";
});
?>
--EXPECTF--
Test 1
ATTR_SERVER_VERSION: string(%d) "%d.%d.%d.%d.%d"
Test 2
ATTR_SERVER_INFO
Found 'Oracle' at position 0 as expected
Done
