--TEST--
SSH2 SFTP subsystem release reclaims its native channel
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $sftp = ssh2_sftp($session);
    if ($sftp === false) {
        throw new RuntimeException('Failed to open the warm-up SFTP subsystem.');
    }
    unset($sftp);
    gc_collect_cycles();

    $baseline = memory_get_usage();

    for ($i = 0; $i < 40; $i++) {
        $sftp = ssh2_sftp($session);
        if ($sftp === false) {
            throw new RuntimeException('Failed to open an SFTP subsystem.');
        }
        unset($sftp);
    }

    gc_collect_cycles();
    var_dump(memory_get_usage() - $baseline < 8192);

    $sftp = ssh2_sftp($session);
    if ($sftp === false) {
        throw new RuntimeException('Failed to reopen the SFTP subsystem.');
    }
    var_dump(ssh2_sftp_realpath($sftp, '.') !== false);

    unset($sftp);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
bool(true)
