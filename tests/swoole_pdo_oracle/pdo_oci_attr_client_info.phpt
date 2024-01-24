--TEST--
swoole_pdo_oracle: Setting session client info
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
	$query = 'select client_info from v$session where sid = sys_context(\'USERENV\', \'SID\')';
    $dbh = PdoOracleTest::create();
	$stmt = $dbh->query($query);
	$row = $stmt->fetch();
	echo 'CLIENT_INFO NOT SET: ';
	var_dump($row['client_info']);

	var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_INFO, "some client info"));

	$stmt = $dbh->query($query);
	$row = $stmt->fetch();
	echo 'CLIENT_INFO SET: ';
	var_dump($row['client_info']);

	var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_INFO, "something else!"));

	$stmt = $dbh->query($query);
	$row = $stmt->fetch();
	echo 'CLIENT_INFO RESET: ';
	var_dump($row['client_info']);

	var_dump($dbh->setAttribute(PDO::OCI_ATTR_CLIENT_INFO, null));

	$stmt = $dbh->query($query);
	$row = $stmt->fetch();
	echo 'CLIENT_INFO NULLED: ';
	var_dump($row['client_info']);

	echo "Done\n";
});
?>
--EXPECT--
CLIENT_INFO NOT SET: NULL
bool(true)
CLIENT_INFO SET: string(16) "some client info"
bool(true)
CLIENT_INFO RESET: string(15) "something else!"
bool(true)
CLIENT_INFO NULLED: NULL
Done
