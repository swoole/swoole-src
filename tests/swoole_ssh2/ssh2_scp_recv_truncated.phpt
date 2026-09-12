--TEST--
ssh2_scp_recv() fails promptly when the peer truncates its announced payload
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_truncated_scp();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    if ($session === false || !ssh2_auth_password(
        $session,
        TEST_SSH2_TRUNCATED_SCP_USER,
        TEST_SSH2_TRUNCATED_SCP_PASS,
    )) {
        throw new RuntimeException('Failed to connect to the truncated SCP fixture.');
    }

    $localFile = sys_get_temp_dir() . '/ssh2_scp_truncated_' . uniqid();
    var_dump(ssh2_scp_recv($session, '/truncated.txt', $localFile) === false);

    if (file_exists($localFile)) {
        unlink($localFile);
    }
    ssh2_disconnect($session);
});
?>
--EXPECTF--
Warning: ssh2_scp_recv(): Error reading from remote file in %s on line %d
bool(true)
