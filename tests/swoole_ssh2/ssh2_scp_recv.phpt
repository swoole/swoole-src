--TEST--
ssh2_scp_recv() - Tests receiving a file via SCP
--CREDITS--
Chris MacPherson
--SKIPIF--
<?php require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php require_once 'ssh2_test.inc';

Co\run(function () {
    $ssh = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    var_dump(ssh2t_auth($ssh));

    // Create a test file on the remote server
    $remote_file = ssh2t_tempnam();
    $remote_content = 'This is test content for SCP receive';

    // Write test content to remote file
    $sftp = ssh2_sftp($ssh);
    $fp = fopen("ssh2.sftp://{$sftp}/{$remote_file}", 'w');
    fwrite($fp, $remote_content);
    fclose($fp);

    // Local file path
    $local_file = sys_get_temp_dir() . '/ssh2_scp_recv_test_' . uniqid();

    // Receive file via SCP
    var_dump(ssh2_scp_recv($ssh, $remote_file, $local_file));

    // Verify the file was received correctly
    var_dump(file_exists($local_file));
    var_dump(file_get_contents($local_file) === $remote_content);

    // Clean up
    unlink($local_file);
    ssh2_sftp_unlink($sftp, $remote_file);
});
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
