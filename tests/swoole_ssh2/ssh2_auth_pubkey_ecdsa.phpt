--TEST--
ssh2_auth_pubkey_file() - Tests authentication with an ECDSA key
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
?>
--FILE--
<?php require_once 'ssh2_test.inc';
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2_auth_pubkey_file($ssh, TEST_SSH2_USER, __DIR__ . '/testkey_ecdsa.pub', __DIR__ . '/testkey_ecdsa'));

    $cmd = ssh2_exec($ssh, 'echo ok');
    stream_set_blocking($cmd, true);
    echo stream_get_contents($cmd);
});
?>
--EXPECT--
bool(true)
ok
