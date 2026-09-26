--TEST--
SSH2 undrained channels release their native state
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

    $channel = ssh2_shell($session, 'xterm');
    if ($channel === false) {
        throw new RuntimeException('Failed to open the warm-up channel.');
    }
    fclose($channel);
    gc_collect_cycles();

    $baseline = memory_get_usage();

    for ($i = 0; $i < 40; $i++) {
        $channel = ssh2_shell($session, 'xterm');
        if ($channel === false) {
            throw new RuntimeException('Failed to open an SSH channel.');
        }
        fclose($channel);
    }

    gc_collect_cycles();
    var_dump(memory_get_usage() - $baseline < 8192);

    $channel = ssh2_exec($session, 'printf usable');
    if ($channel === false) {
        throw new RuntimeException('Failed to open the final SSH channel.');
    }
    var_dump(stream_get_contents($channel));

    fclose($channel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
string(6) "usable"
