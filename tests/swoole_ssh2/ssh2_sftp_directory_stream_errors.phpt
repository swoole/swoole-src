--TEST--
SFTP directory streams distinguish read errors from clean completion
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

    $sessionBaseline = count(get_resources('SSH2 Session'));
    $sftpBaseline    = count(get_resources('SSH2 SFTP'));
    $root            = ssh2t_tempnam();
    $session         = $connect();
    $sftp            = ssh2_sftp($session);

    if ($sftp === false
        || !ssh2_sftp_mkdir($sftp, $root, 0700)
        || file_put_contents('ssh2.sftp://' . (int) $sftp . $root . '/alpha.txt', 'alpha') !== 5
        || file_put_contents('ssh2.sftp://' . (int) $sftp . $root . '/beta.txt', 'beta') !== 4) {
        throw new RuntimeException('Failed to create the SFTP directory fixture.');
    }

    $directoryUrl = 'ssh2.sftp://' . (int) $sftp . $root;
    $directory    = opendir($directoryUrl);

    if ($directory === false) {
        throw new RuntimeException('Failed to open the SFTP directory fixture.');
    }

    $entries = [];

    while (($entry = readdir($directory)) !== false) {
        $entries[] = $entry;
    }

    $expected = ['.', '..', 'alpha.txt', 'beta.txt'];
    sort($entries, SORT_STRING);
    sort($expected, SORT_STRING);

    var_dump($entries === $expected);
    var_dump(feof($directory));
    closedir($directory);

    $failedDirectory = opendir($directoryUrl);

    if ($failedDirectory === false) {
        throw new RuntimeException('Failed to open the SFTP failure directory.');
    }

    var_dump(ssh2_disconnect($session));
    var_dump(readdir($failedDirectory) === false);
    var_dump(feof($failedDirectory) === false);
    closedir($failedDirectory);
    unset($failedDirectory, $directory, $sftp, $session);

    $session = $connect();
    $sftp    = ssh2_sftp($session);

    if ($sftp === false
        || !ssh2_sftp_unlink($sftp, $root . '/alpha.txt')
        || !ssh2_sftp_unlink($sftp, $root . '/beta.txt')
        || !ssh2_sftp_rmdir($sftp, $root)) {
        throw new RuntimeException('Failed to clean up the SFTP directory fixture.');
    }

    unset($sftp);
    ssh2_disconnect($session);
    unset($session);
    gc_collect_cycles();

    var_dump(count(get_resources('SSH2 SFTP')) === $sftpBaseline);
    var_dump(count(get_resources('SSH2 Session')) === $sessionBaseline);
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
