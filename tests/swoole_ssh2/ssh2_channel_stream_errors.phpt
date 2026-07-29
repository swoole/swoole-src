--TEST--
Blocking SSH2 channels preserve errors and derive EOF after reads
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

    $writeChannel = ssh2_exec($session, 'cat >/dev/null; sleep 5');

    if ($writeChannel === false) {
        throw new RuntimeException('Failed to open the SSH write channel.');
    }

    stream_set_blocking($writeChannel, true);

    var_dump(ssh2_send_eof($writeChannel));
    var_dump(fwrite($writeChannel, 'x'));
    var_dump(stream_get_meta_data($writeChannel)['eof']);

    fclose($writeChannel);

    $readChannel = ssh2_exec($session, 'true');

    if ($readChannel === false) {
        throw new RuntimeException('Failed to open the SSH read channel.');
    }

    stream_set_blocking($readChannel, true);

    var_dump(fread($readChannel, 1) === '');
    var_dump(feof($readChannel));

    fclose($readChannel);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
bool(false)
bool(false)
bool(true)
bool(true)
