--TEST--
ssh2_sftp: wrapper paths keep '#' and '?', and root URLs stay intact
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php require_once 'ssh2_test.inc';
Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    ssh2t_auth($ssh);
    $sftp = ssh2_sftp($ssh);

    foreach (['#', '?'] as $char) {
        $filename = ssh2t_tempnam() . "-a{$char}b";
        file_put_contents("ssh2.sftp://{$sftp}/{$filename}", 'data');
        var_dump(ssh2_sftp_stat($sftp, $filename)['size']);
        var_dump(ssh2_sftp_unlink($sftp, $filename));
    }

    var_dump(is_dir("ssh2.sftp://{$sftp}/"));
    var_dump(is_dir('ssh2.sftp://' . intval($sftp) . '/'));
});
?>
--EXPECT--
int(4)
bool(true)
int(4)
bool(true)
bool(true)
bool(true)
