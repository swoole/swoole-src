--TEST--
swoole_pdo_oracle: PECL PDO_OCI Bug #6364 (segmentation fault on stored procedure call with OUT binds)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
<?php
if (getenv('SKIP_ASAN')) die('skip leaks memory under asan');
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
    $dbh->exec ("create table bug_6364_t (c1 varchar2(10), c2 varchar2(10), c3 varchar2(10), c4 varchar2(10), c5 varchar2(10))");

    $dbh->exec ("create or replace procedure bug_6364_sp(p1 IN varchar2, p2 IN varchar2, p3 IN varchar2, p4 OUT varchar2, p5 OUT varchar2) as begin insert into bug_6364_t (c1, c2, c3) values (p1, p2, p3); p4 := 'val4'; p5 := 'val5'; end;");

    $stmt = $dbh->prepare("call bug_6364_sp('p1','p2','p3',?,?)");

    $out_param1 = "a";
    $out_param2 = "a";

    $stmt->bindParam(1, $out_param1,PDO::PARAM_STR, 1024);
    $stmt->bindParam(2, $out_param2,PDO::PARAM_STR, 1024);

    $stmt->execute() or die ("Execution error: " . var_dump($dbh->errorInfo()));

    var_dump($out_param1);
    var_dump($out_param2);

    foreach ($dbh->query("select * from bug_6364_t") as $row) {
        var_dump($row);
    }

    print "Done\n";

    // Cleanup
    $dbh->exec ("drop procedure bug_6364_sp");
    $dbh->exec ("drop table bug_6364_t");
});
?>
--EXPECT--
string(4) "val4"
string(4) "val5"
array(10) {
  ["c1"]=>
  string(2) "p1"
  [0]=>
  string(2) "p1"
  ["c2"]=>
  string(2) "p2"
  [1]=>
  string(2) "p2"
  ["c3"]=>
  string(2) "p3"
  [2]=>
  string(2) "p3"
  ["c4"]=>
  NULL
  [3]=>
  NULL
  ["c5"]=>
  NULL
  [4]=>
  NULL
}
Done
