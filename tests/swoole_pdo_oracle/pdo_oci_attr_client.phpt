--TEST--
swoole_pdo_oracle: Client version
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
    echo "ATTR_CLIENT_VERSION: ";
    $cv = $dbh->getAttribute(PDO::ATTR_CLIENT_VERSION);
    var_dump($cv);

    $s = explode(".", $cv);
    if (count($s) > 1 && (($s[0] == 10 && $s[1] >= 2) || $s[0] >= 11)) {
        if (count($s) != 5) {
            echo "Wrong number of values in array\nVersion was: ";
            var_dump($cv);
        } else {
            echo "Version OK, so far as can be portably checked\n";
        }
    } else {
        if (count($s) != 2) {
            echo "Wrong number of values in array\nVersion was: ";
            var_dump($cv);
        } else {
            echo "Version OK, so far as can be portably checked\n";
        }
    }

    echo "Done\n";
});
?>
--EXPECTF--
ATTR_CLIENT_VERSION: string(%d) "%d.%s"
Version OK, so far as can be portably checked
Done
