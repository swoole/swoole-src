--TEST--
SSH2 session release cancels a coroutine bound to its socket safely
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
        throw new RuntimeException('Failed to open an SSH channel.');
    }
});

$readerState = 'created';
$contents = null;

go(function () use ($channel, &$readerState, &$contents): void {
    $readerState = 'reading';
    $contents = stream_get_contents($channel);
    $readerState = 'complete';
});

var_dump($readerState);
ssh2_disconnect($session);
var_dump($readerState);
Swoole\Event::wait();

var_dump($readerState);
var_dump($contents);
fclose($channel);
?>
--EXPECT--
string(7) "reading"
string(8) "complete"
string(8) "complete"
string(0) ""
