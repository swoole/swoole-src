--TEST--
swoole_pdo_oracle: Oracle Nulls
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

function do_query($dbh)
{
    var_dump($dbh->getAttribute(PDO::ATTR_ORACLE_NULLS));
    $s = $dbh->prepare("select '' as myempty, null as mynull from dual");
    $s->execute();
    while ($r = $s->fetch()) {
        var_dump($r[0]);
        var_dump($r[1]);
    }
}

Co::set(['hook_flags'=> SWOOLE_HOOK_PDO_ORACLE]);
run(function() {
    $dbh = PdoOracleTest::create();
    print "PDO::ATTR_ORACLE_NULLS: Default: ";
    do_query($dbh);

    print "PDO::ATTR_ORACLE_NULLS: PDO::NULL_NATURAL: ";
    $dbh->setAttribute(PDO::ATTR_ORACLE_NULLS, PDO::NULL_NATURAL); // No conversion.

    do_query($dbh);

    print "PDO::ATTR_ORACLE_NULLS: PDO::NULL_EMPTY_STRING: ";
    $dbh->setAttribute(PDO::ATTR_ORACLE_NULLS, PDO::NULL_EMPTY_STRING); // Empty string is converted to NULL.

    do_query($dbh);

    print "PDO::ATTR_ORACLE_NULLS: PDO::NULL_TO_STRING: ";
    $dbh->setAttribute(PDO::ATTR_ORACLE_NULLS, PDO::NULL_TO_STRING); // NULL is converted to an empty string.

    do_query($dbh);

    echo "Done\n";
});
?>
--EXPECT--
PDO::ATTR_ORACLE_NULLS: Default: int(0)
NULL
NULL
PDO::ATTR_ORACLE_NULLS: PDO::NULL_NATURAL: int(0)
NULL
NULL
PDO::ATTR_ORACLE_NULLS: PDO::NULL_EMPTY_STRING: int(1)
NULL
NULL
PDO::ATTR_ORACLE_NULLS: PDO::NULL_TO_STRING: int(2)
string(0) ""
string(0) ""
Done
