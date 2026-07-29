--TEST--
One-shot SFTP wrapper operations release their SFTP and session references
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
    $sessionBaseline = count(get_resources('SSH2 Session'));
    $sftpBaseline    = count(get_resources('SSH2 SFTP'));
    $session         = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $sftp = ssh2_sftp($session);

    if ($sftp === false) {
        throw new RuntimeException('Failed to open the SFTP subsystem.');
    }

    $root       = ssh2t_tempnam();
    $rootUrl    = 'ssh2.sftp://' . (int) $sftp . $root;
    $sourceUrl  = $rootUrl . '/source.txt';
    $targetUrl  = $rootUrl . '/target.txt';
    $missingUrl = $rootUrl . '/missing.txt';

    var_dump(mkdir($rootUrl, 0700));
    var_dump(file_put_contents($sourceUrl, 'test') === 4);

    clearstatcache(true, $sourceUrl);
    var_dump(file_exists($sourceUrl));

    clearstatcache(true, $missingUrl);
    var_dump(!file_exists($missingUrl));

    var_dump(rename($sourceUrl, $targetUrl));
    var_dump(unlink($targetUrl));
    var_dump(rmdir($rootUrl));

    unset($sftp, $session);
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
bool(true)
bool(true)
