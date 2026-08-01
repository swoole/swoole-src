--TEST--
SSH2 exec metadata remains readable during IO and reports exit signals
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

    $channel = ssh2_exec($session, "printf output; exec 1>&- 2>&-; sleep 1; exit 7");

    if ($channel === false) {
        throw new RuntimeException('Failed to open the exec channel.');
    }

    $contents = null;
    $cid = go(function () use ($channel, &$contents): void {
        $contents = stream_get_contents($channel);
    });

    Co::sleep(0.05);
    $metadata = stream_get_meta_data($channel);
    var_dump($metadata['exit_status']);
    var_dump($metadata['exit_signal']);

    if (!Swoole\Coroutine::join([$cid], 5)) {
        throw new RuntimeException('Timed out waiting for the exec reader.');
    }

    var_dump($contents);
    $metadata = stream_get_meta_data($channel);
    var_dump($metadata['exit_status']);
    var_dump($metadata['exit_signal']);

    $signalled = ssh2_exec($session, 'kill -KILL $$');

    if ($signalled === false) {
        throw new RuntimeException('Failed to open the signalled exec channel.');
    }

    stream_get_contents($signalled);
    $metadata = stream_get_meta_data($signalled);
    var_dump($metadata['exit_status']);
    var_dump($metadata['exit_signal']);

    fclose($channel);
    fclose($signalled);
    ssh2_disconnect($session);
});
?>
--EXPECT--
int(0)
NULL
string(6) "output"
int(7)
NULL
int(0)
string(4) "KILL"
