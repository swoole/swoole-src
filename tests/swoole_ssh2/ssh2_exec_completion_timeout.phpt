--TEST--
SSH2 exec completion preserves timeout metadata and remains retryable
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co::set(['socket_timeout' => 0.3]);

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $channel = ssh2_exec($session, "exec 1>&- 2>&-; sleep 1; exit 7");

    if ($channel === false) {
        throw new RuntimeException('Failed to open the exec channel.');
    }

    $startedAt = microtime(true);
    var_dump(fread($channel, 1));
    $elapsed = microtime(true) - $startedAt;
    $metadata = stream_get_meta_data($channel);

    var_dump($elapsed >= 0.2 && $elapsed < 0.8);
    var_dump($metadata['timed_out']);
    var_dump($metadata['eof']);

    stream_set_timeout($channel, 2);
    var_dump(stream_get_contents($channel));

    $metadata = stream_get_meta_data($channel);
    var_dump($metadata['timed_out']);
    var_dump($metadata['eof']);
    var_dump($metadata['exit_status']);

    fclose($channel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(false)
bool(true)
bool(true)
bool(false)
string(0) ""
bool(false)
bool(true)
int(7)
