--TEST--
SSH2 session destruction closes its socket after a thread fatal error
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
skip_if_not_linux();
skip_if_nts();
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

use Swoole\Thread;

function countSocketDescriptors(): int
{
    $count = 0;
    foreach (glob('/proc/self/fd/*') ?: [] as $path) {
        $target = @readlink($path);
        if ($target !== false && str_starts_with($target, 'socket:[')) {
            $count++;
        }
    }
    return $count;
}

if (empty(Thread::getArguments())) {
    $before = countSocketDescriptors();
    $thread = new Thread(__FILE__, 'child');
    $thread->join();

    var_dump(countSocketDescriptors() === $before);
} else {
    ini_set('display_errors', '0');
    ini_set('log_errors', '0');

    $session = $channel = null;

    Co\run(function () use (&$session, &$channel): void {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
        if ($session === false || !ssh2t_auth($session)) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }

        $channel = ssh2_exec($session, 'sleep 30');
        if ($channel === false) {
            throw new RuntimeException('Failed to open an SSH channel.');
        }

        go(function () use ($channel): void {
            stream_get_contents($channel);
        });

        swoole_implicit_fn('fatal_error');
    });
}
?>
--EXPECT--
bool(true)
