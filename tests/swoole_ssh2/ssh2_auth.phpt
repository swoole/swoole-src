--TEST--
ssh2_auth_FOO() - Attempt to authenticate to a remote host
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php
require_once 'ssh2_test.inc';
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($ssh));
});
?>
--EXPECT--
bool(true)
