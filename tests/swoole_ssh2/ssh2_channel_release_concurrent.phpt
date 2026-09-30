--TEST--
SSH2 channel and listener release remains safe while another coroutine owns the session socket
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

$session = $channelA = $channelB = $listener = null;

Co\run(function () use (&$session, &$channelA, &$channelB, &$listener): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $channelA = ssh2_exec($session, 'sleep 1; printf channel-a-done');
    $channelB = ssh2_exec($session, 'sleep 5');
    $listener = ssh2_forward_listen($session, 0);

    if ($channelA === false || $channelB === false || $listener === false) {
        throw new RuntimeException('Failed to create the SSH fixtures.');
    }
});

$readerState = 'created';
$contents = null;

go(function () use ($channelA, &$readerState, &$contents): void {
    $readerState = 'reading';
    $contents = stream_get_contents($channelA);
    $readerState = 'complete';
});

var_dump($readerState);
fclose($channelB);
unset($listener);
gc_collect_cycles();

Swoole\Event::wait();

var_dump($readerState);
var_dump($contents);

Co\run(function () use ($session): void {
    $channel = ssh2_exec($session, 'printf usable');
    if ($channel === false) {
        throw new RuntimeException('Failed to reuse the SSH session.');
    }
    var_dump(stream_get_contents($channel));
    fclose($channel);
});

fclose($channelA);
ssh2_disconnect($session);
?>
--EXPECT--
string(7) "reading"
string(8) "complete"
string(14) "channel-a-done"
string(6) "usable"
