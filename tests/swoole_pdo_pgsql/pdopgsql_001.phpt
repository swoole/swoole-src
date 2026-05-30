--TEST--
swoole_pdo_pgsql: subclass basic
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

    $db->query("DROP TABLE IF EXISTS pdopgsql_001");
    $db->query('CREATE TABLE pdopgsql_001 (id INT, name TEXT)');
    $db->query("INSERT INTO pdopgsql_001 VALUES (NULL, 'PHP'), (NULL, 'PHP6')");

    foreach ($db->query('SELECT name FROM pdopgsql_001') as $row) {
        var_dump($row);
    }

    echo "Fin.";
});
?>
--EXPECT--
array(2) {
  ["name"]=>
  string(3) "PHP"
  [0]=>
  string(3) "PHP"
}
array(2) {
  ["name"]=>
  string(4) "PHP6"
  [0]=>
  string(4) "PHP6"
}
Fin.