--TEST--
SSH2 resource release balances native allocations while the session remains open
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_needs_native_audit();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';
require __DIR__ . '/ssh2_release_test.inc';

if (($argv[1] ?? null) !== 'child') {
    ssh2t_run_with_native_audit(__FILE__);
    exit;
}

function checkNativeRelease(string $name, callable $release): void
{
    // Warm up any session-owned buffers before measuring outstanding native allocations.
    for ($i = 0; $i < 3; $i++) {
        $release();
    }
    $before = ssh2t_native_counters()['live'];
    for ($i = 0; $i < 10; $i++) {
        $release();
    }
    $after = ssh2t_native_counters()['live'];
    if ($after > $before) {
        throw new RuntimeException("{$name} leaked native allocations: {$before} -> {$after}");
    }
    echo "{$name}: released\n";
}

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }
    $counts = ssh2t_native_counters();
    if ($counts['sessions'] !== 1 || $counts['allocations'] === 0 || $counts['live'] === 0) {
        throw new RuntimeException('The fixture did not observe libssh2 allocations.');
    }

    checkNativeRelease('channel', static function () use ($session): void {
        $channel = ssh2_shell($session, 'xterm');
        if ($channel === false) {
            throw new RuntimeException('Failed to open an SSH channel.');
        }
        fclose($channel);
    });
    checkNativeRelease('sftp', static function () use ($session): void {
        $sftp = ssh2_sftp($session);
        if ($sftp === false) {
            throw new RuntimeException('Failed to open an SFTP subsystem.');
        }
        unset($sftp);
    });
    checkNativeRelease('listener', static function () use ($session): void {
        $listener = ssh2_forward_listen($session, 0);
        if ($listener === false) {
            throw new RuntimeException('Failed to open a forwarding listener.');
        }
        unset($listener);
    });

    ssh2_disconnect($session);
    unset($session);
    $counts = ssh2t_native_counters();
    if ($counts['live'] !== 0 || $counts['allocations'] !== $counts['frees'] || $counts['session_frees'] !== 1) {
        throw new RuntimeException('Session teardown left native allocations behind: ' . json_encode($counts));
    }
    echo "session: released\n";
});
?>
--EXPECT--
channel: released
sftp: released
listener: released
session: released
