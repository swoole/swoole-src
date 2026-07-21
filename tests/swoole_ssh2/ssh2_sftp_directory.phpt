--TEST--
SFTP directory streams enumerate remote entries
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
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $sftp = ssh2_sftp($session);

    if ($sftp === false) {
        throw new RuntimeException('Failed to open the SFTP subsystem.');
    }

    $root    = ssh2t_tempnam();
    $rootUrl = 'ssh2.sftp://' . (int) $sftp . $root;

    if (!ssh2_sftp_mkdir($sftp, $root, 0700)
        || file_put_contents($rootUrl . '/alpha.txt', 'alpha') !== 5
        || file_put_contents($rootUrl . '/beta.txt', 'beta') !== 4) {
        throw new RuntimeException('Failed to create the SFTP directory fixture.');
    }

    $directory = opendir($rootUrl);

    if ($directory === false) {
        throw new RuntimeException('Failed to open the SFTP directory fixture.');
    }

    $entries = [];

    while (($entry = readdir($directory)) !== false) {
        $entries[] = $entry;
    }

    closedir($directory);

    $expected = ['.', '..', 'alpha.txt', 'beta.txt'];
    sort($entries, SORT_STRING);
    sort($expected, SORT_STRING);

    var_dump($entries === $expected);

    if (!ssh2_sftp_unlink($sftp, $root . '/alpha.txt')
        || !ssh2_sftp_unlink($sftp, $root . '/beta.txt')
        || !ssh2_sftp_rmdir($sftp, $root)) {
        throw new RuntimeException('Failed to clean up the SFTP directory fixture.');
    }
});
?>
--EXPECT--
bool(true)
