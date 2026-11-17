--TEST--
SSH2 session free failures close the transport descriptor
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_native_audit();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';
require __DIR__ . '/ssh2_release_test.inc';

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

if (($argv[1] ?? null) === 'child') {
    Co\run(function (): void {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
        if ($session === false) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }

        $connected = countSocketDescriptors();
        ssh2_disconnect($session);

        var_dump(countSocketDescriptors() === $connected - 1);
    });
    exit;
}

ssh2t_run_with_native_audit(__FILE__, true);
?>
--EXPECTF--
Warning: ssh2_disconnect(): Unable to free SSH2 session(-9): %S; resources retained in %s on line %d
bool(true)
