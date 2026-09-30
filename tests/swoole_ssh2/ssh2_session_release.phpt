--TEST--
SSH2 session destruction reclaims attached channels and listeners
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $release = static function (bool $withListener): void {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

        if ($session === false || !ssh2t_auth($session)) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }

        $channel = ssh2_exec($session, 'sleep 5');
        $listener = $withListener ? ssh2_forward_listen($session, 0) : null;

        if ($channel === false || ($withListener && $listener === false)) {
            throw new RuntimeException('Failed to create the SSH fixtures.');
        }

        ssh2_disconnect($session);
        fclose($channel);
        unset($listener, $session);
        gc_collect_cycles();
    };

    $release(false);
    $baseline = memory_get_usage();

    for ($i = 0; $i < 10; $i++) {
        $release($i === 0);
    }

    var_dump(memory_get_usage() - $baseline < 65536);
});
?>
--EXPECT--
bool(true)
