--TEST--
SSH2 channel release can yield in a coroutine entered during request shutdown
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

    $channel = ssh2_exec($session, 'sleep 1');
    if ($channel === false) {
        throw new RuntimeException('Failed to open an SSH channel.');
    }
});

register_shutdown_function(static function () use ($session, $channel): void {
    Co\run(static function () use ($channel): void {
        $ticked = false;
        go(static function () use (&$ticked): void {
            Co::sleep(0.1);
            $ticked = true;
        });

        fclose($channel);
        var_dump($ticked);
    });
    ssh2_disconnect($session);
    echo "shutdown coroutine\n";
});
?>
--EXPECT--
bool(true)
shutdown coroutine
