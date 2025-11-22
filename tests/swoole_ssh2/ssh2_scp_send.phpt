--TEST--
ssh2_scp_send() - Tests sending a file via SCP
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

    // Create a test file locally
    $local_file = sys_get_temp_dir() . '/ssh2_scp_send_test_' . uniqid();
    $test_content = 'This is test content for SCP send';
    file_put_contents($local_file, $test_content);

    // Remote file path
    $remote_file = ssh2t_tempnam();

    // Send file via SCP
    var_dump(ssh2_scp_send($ssh, $local_file, $remote_file, 0644));

    // Verify the file was sent correctly
    $sftp = ssh2_sftp($ssh);
    $remote_content = file_get_contents("ssh2.sftp://{$sftp}/{$remote_file}");
    var_dump($remote_content === $test_content);

    // Clean up
    unlink($local_file);
    ssh2_sftp_unlink($sftp, $remote_file);
});
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
