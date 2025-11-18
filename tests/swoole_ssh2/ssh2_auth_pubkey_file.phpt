--TEST--
ssh2_auth_pubkey_file() - Tests authentication with a key
--SKIPIF--
<?php require('ssh2_skip.inc'); ?>
--FILE--
<?php require('ssh2_test.inc');

$ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

var_dump(ssh2_auth_pubkey_file($ssh, TEST_SSH2_USER, TEST_SSH2_PUB_KEY, TEST_SSH2_PRIV_KEY));

$cmd=ssh2_exec($ssh, 'echo "testing echo with key auth"' . PHP_EOL);

var_dump($cmd);

stream_set_blocking($cmd, true);
$response = stream_get_contents($cmd);
echo $response . PHP_EOL;

--EXPECTF--
bool(true)
resource(%d) of type (stream)
testing echo with key auth

