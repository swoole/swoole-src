--TEST--
Bug 79631 (SSH disconnect segfault with SFTP (assertion failed))
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require_once 'ssh2_test.inc';
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    ssh2t_auth($ssh);
    $sftp = ssh2_sftp($ssh);
    ssh2_disconnect($ssh);
    echo "done\n";
});
?>
--EXPECT--
done
