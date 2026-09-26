--TEST--
SSH2 remote-forward listeners release without invalidating their session
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

    $listener = ssh2_forward_listen($session, 0);
    if ($listener === false) {
        throw new RuntimeException('Failed to create the first listener.');
    }
    unset($listener);

    $listener = ssh2_forward_listen($session, 0);
    if ($listener === false) {
        throw new RuntimeException('Failed to create the second listener.');
    }
    unset($listener);

    $channel = ssh2_exec($session, 'printf usable');
    if ($channel === false) {
        throw new RuntimeException('Failed to reuse the SSH session.');
    }
    var_dump(stream_get_contents($channel));

    fclose($channel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
string(6) "usable"
