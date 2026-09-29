--TEST--
ssh2_shell() waits for the remote exit status
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php
require_once 'ssh2_test.inc';

Co\run(function () {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $shell = ssh2_shell($session);

    if ($shell === false) {
        throw new RuntimeException('Failed to open the shell channel.');
    }

    fwrite($shell, "exec sh -c 'exec 0<&- 1>&- 2>&-; sleep 1; exit 23'\n");
    stream_get_contents($shell);

    var_dump(stream_get_meta_data($shell)['exit_status']);

    fclose($shell);
    ssh2_disconnect($session);
});
?>
--EXPECT--
int(23)
