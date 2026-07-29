--TEST--
Nonblocking SSH2 channels distinguish backpressure from terminal errors
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

    $channel = ssh2_exec($session, 'cat >/dev/null; sleep 5');

    if ($channel === false) {
        throw new RuntimeException('Failed to open the SSH channel.');
    }

    var_dump(stream_get_meta_data($channel)['blocked']);
    stream_set_blocking($channel, false);
    var_dump(stream_get_meta_data($channel)['blocked']);

    var_dump(fread($channel, 1) === '');
    var_dump(stream_get_meta_data($channel)['eof']);
    var_dump(ssh2_send_eof($channel));
    var_dump(fwrite($channel, 'x'));
    var_dump(stream_get_meta_data($channel)['eof']);

    fclose($channel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)
bool(false)
