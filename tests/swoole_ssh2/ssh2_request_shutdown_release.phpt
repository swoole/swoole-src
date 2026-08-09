--TEST--
SSH2 request shutdown releases undrained channels and callback state cleanly
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

$session = $channels = null;

Co\run(function () use (&$session, &$channels): void {
    $session = ssh2_connect(
        TEST_SSH2_HOSTNAME,
        TEST_SSH2_PORT,
        null,
        ['disconnect' => static function (): void {}],
    );

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $channels = [];
    for ($i = 0; $i < 5; $i++) {
        $channel = ssh2_exec($session, 'sleep 5');
        if ($channel === false) {
            throw new RuntimeException('Failed to open an SSH channel.');
        }
        stream_set_timeout($channel, 0, 50000);
        $channels[] = $channel;
    }
});

register_shutdown_function(static function () use ($channels): void {
    foreach ($channels as $channel) {
        fclose($channel);
    }
    echo "shutdown\n";
});
?>
--EXPECT--
shutdown
