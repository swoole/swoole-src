--TEST--
ssh2_shell() accepts width and height without an explicit unit
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php
require_once 'ssh2_test.inc';

Co\run(function () {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($session));

    $shell = ssh2_shell($session, 'xterm', null, 80, 24);
    var_dump(is_resource($shell));

    if (is_resource($shell)) {
        fclose($shell);
    }

    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
bool(true)
