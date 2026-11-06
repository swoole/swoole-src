--TEST--
ssh2_set_timeout() - Tests session timeouts
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth(); ?>
--FILE--
<?php require_once 'ssh2_test.inc';
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($ssh));

    $cmd = ssh2_exec($ssh, 'sleep 1; printf x');
    stream_set_blocking($cmd, true);

    ssh2_set_timeout($ssh, 0, 200000);
    $startedAt = microtime(true);
    var_dump(fread($cmd, 1));
    var_dump(microtime(true) - $startedAt < 0.9);
    var_dump(stream_get_meta_data($cmd)['timed_out']);

    ssh2_set_timeout($ssh, 0);
    var_dump(fread($cmd, 1));
});
?>
--EXPECT--
bool(true)
bool(false)
bool(true)
bool(true)
string(1) "x"
