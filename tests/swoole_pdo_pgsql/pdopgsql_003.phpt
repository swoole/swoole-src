--TEST--
Pdo\swoole_pdo_pgsql getWarningCount
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use function Swoole\Coroutine\run;
run(function() {
    $host = PGSQL_HOST;
    $port = PGSQL_PORT;
    $user = PGSQL_USER;
    $password = PGSQL_PASSWORD;
    $dbname = PGSQL_DBNAME;
    $db = PDO::connect("pgsql:host={$host};port={$port};dbname={$dbname}", $user, $password);
    Assert::true($db instanceof \Pdo\Pgsql);

    echo $db->escapeIdentifier("This is a quote\"") . "\n";
    try {
        $db->escapeIdentifier("aa\xC3\xC3\xC3");
    } catch (PDOException $e) {
        echo $e->getMessage() . "\n";
    }
});
?>
--EXPECTF--
"This is a quote"""
SQLSTATE[HY000]: General error: 7 %r(incomplete|invalid)%r multibyte character
