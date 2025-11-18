--TEST--
ssh2_shell_test() - Tests opening a shell
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));

$cmd=ssh2_exec($ssh, 'echo "testing echo"' . PHP_EOL);

var_dump($cmd);

stream_set_blocking($cmd, true);
$response = stream_get_contents($cmd);
echo $response . PHP_EOL;

--EXPECTF--
bool(true)
resource(%d) of type (stream)
testing echo

