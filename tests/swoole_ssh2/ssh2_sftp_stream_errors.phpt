--TEST--
SFTP streams distinguish read errors from clean EOF
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $connect = static function () {
        $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

        if ($session === false || !ssh2t_auth($session)) {
            throw new RuntimeException('Failed to connect to the SSH fixture.');
        }

        return $session;
    };

    $root     = ssh2t_tempnam();
    $filePath = $root . '/file.txt';
    $session  = $connect();
    $sftp     = ssh2_sftp($session);

    if ($sftp === false
        || !ssh2_sftp_mkdir($sftp, $root, 0700)
        || file_put_contents('ssh2.sftp://' . (int) $sftp . $filePath, 'test') !== 4) {
        throw new RuntimeException('Failed to create the SFTP fixture.');
    }

    $failedRead = fopen('ssh2.sftp://' . (int) $sftp . $filePath, 'rb');

    if ($failedRead === false) {
        throw new RuntimeException('Failed to open the SFTP error stream.');
    }

    var_dump(ssh2_disconnect($session));
    var_dump(fread($failedRead, 1) === false);
    var_dump(feof($failedRead) === false);
    fclose($failedRead);
    unset($failedRead, $sftp, $session);

    $session   = $connect();
    $sftp      = ssh2_sftp($session);
    $cleanRead = $sftp === false
        ? false
        : fopen('ssh2.sftp://' . (int) $sftp . $filePath, 'rb');

    if ($cleanRead === false) {
        throw new RuntimeException('Failed to open the SFTP EOF stream.');
    }

    var_dump(fread($cleanRead, 4) === 'test');
    var_dump(fread($cleanRead, 1) === '');
    var_dump(feof($cleanRead));
    fclose($cleanRead);

    if (!ssh2_sftp_unlink($sftp, $filePath) || !ssh2_sftp_rmdir($sftp, $root)) {
        throw new RuntimeException('Failed to clean up the SFTP fixture.');
    }

    unset($cleanRead, $sftp);
    ssh2_disconnect($session);
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
