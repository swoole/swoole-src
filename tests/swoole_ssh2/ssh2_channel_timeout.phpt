--TEST--
SSH2 channels preserve sub-second stream timeouts
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

    $timedChannel   = ssh2_exec($session, 'sleep 2; printf x');
    $untimedChannel = ssh2_exec($session, 'sleep 1; printf y');

    if ($timedChannel === false || $untimedChannel === false) {
        throw new RuntimeException('Failed to open the SSH channels.');
    }

    stream_set_timeout($timedChannel, 0, 200000);

    $startedAt = microtime(true);
    var_dump(fread($timedChannel, 1));
    $elapsed = microtime(true) - $startedAt;

    var_dump($elapsed >= 0.1 && $elapsed < 1.0);
    var_dump(stream_get_meta_data($timedChannel)['timed_out']);

    stream_set_blocking($timedChannel, false);
    var_dump(fread($timedChannel, 1) === '');
    var_dump(stream_get_meta_data($timedChannel)['timed_out']);

    $startedAt = microtime(true);
    var_dump(fread($untimedChannel, 1));
    var_dump(microtime(true) - $startedAt >= 0.5);
    var_dump(stream_get_meta_data($untimedChannel)['timed_out']);

    fclose($timedChannel);
    fclose($untimedChannel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(false)
bool(true)
bool(true)
bool(true)
bool(false)
string(1) "y"
bool(true)
bool(false)
