--TEST--
ssh2_send_eof() - Tests closing standard input
--SKIPIF--
<?php require('ssh2_skip.inc'); ssh2t_needs_auth(); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
var_dump(ssh2t_auth($ssh));

$cmd=ssh2_exec($ssh, "cat\n");

var_dump($cmd);

stream_set_blocking($cmd, true);

$content = "foo";

fwrite($cmd, $content);
fflush($cmd);
ssh2_send_eof($cmd);

$response = stream_get_contents($cmd);
var_dump($response === $content);
echo $response . PHP_EOL;

--EXPECTF--
bool(true)
resource(%d) of type (stream)
bool(true)
foo

