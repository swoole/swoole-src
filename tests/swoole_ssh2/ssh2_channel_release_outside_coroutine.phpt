--TEST--
SSH2 channel release outside a coroutine restores the session's nonblocking mode
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

$session = $channel = null;

Co\run(function () use (&$session, &$channel): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $channel = ssh2_exec($session, 'sleep 5');
    if ($channel === false) {
        throw new RuntimeException('Failed to open the SSH channel.');
    }
});

fclose($channel);

Co\run(function () use ($session): void {
    $ticked = false;
    go(function () use (&$ticked): void {
        Co::sleep(0.1);
        $ticked = true;
    });

    $channel = ssh2_exec($session, 'sleep 1; printf usable');
    if ($channel === false) {
        throw new RuntimeException('Failed to reuse the SSH session.');
    }

    var_dump(stream_get_contents($channel));
    var_dump($ticked);
    fclose($channel);
});

ssh2_disconnect($session);
?>
--EXPECT--
string(6) "usable"
bool(true)
