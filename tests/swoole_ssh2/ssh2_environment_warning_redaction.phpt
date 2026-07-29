--TEST--
SSH2 environment failure warnings redact values
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php
require_once 'ssh2_test.inc';

Co\run(function () {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($session));

    // The fixture accepts only SWOOLE_TEST_*, so OpenSSH rejects this variable
    // and both forwarding paths emit their setenv warning.
    $environment = ['SWOOLE_REJECTED_SECRET' => 'value-must-not-appear'];

    $shell = ssh2_shell($session, 'xterm', $environment, 80, 24);

    if (is_resource($shell)) {
        fclose($shell);
    }

    $stream = ssh2_exec($session, 'true', 'xterm', $environment);

    if (is_resource($stream)) {
        fclose($stream);
    }

    ssh2_disconnect($session);
});
?>
--EXPECTF--
bool(true)%w
Warning: ssh2_shell(): Failed setting environment variable SWOOLE_REJECTED_SECRET on remote end in %s on line %d%w
Warning: ssh2_exec(): Failed setting environment variable SWOOLE_REJECTED_SECRET on remote end in %s on line %d
