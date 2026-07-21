--TEST--
ssh2_exec() pairs every environment key with its own value
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php
require_once 'ssh2_test.inc';

Co\run(function () {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($session));

    $stream = ssh2_exec(
        $session,
        'printf "%s|%s" "$SWOOLE_TEST_A" "$SWOOLE_TEST_B"',
        null,
        [
            'SWOOLE_TEST_A' => 'alpha',
            'SWOOLE_TEST_B' => 'bravo',
        ],
    );

    if ($stream === false) {
        throw new RuntimeException('Failed to execute the environment command.');
    }

    stream_set_blocking($stream, true);
    var_dump(stream_get_contents($stream));

    fclose($stream);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
string(11) "alpha|bravo"
