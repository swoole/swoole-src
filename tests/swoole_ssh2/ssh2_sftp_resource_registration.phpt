--TEST--
Direct SFTP wrapper connections register and release their subsystem resource
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();

if (TEST_SSH2_AUTH !== 'password') {
    echo 'skip direct wrapper test requires password authentication';
}
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $sessionBaseline = count(get_resources('SSH2 Session'));
    $sftpBaseline    = count(get_resources('SSH2 SFTP'));
    $context         = stream_context_create([
        'ssh2' => [
            'username' => TEST_SSH2_USER,
            'password' => TEST_SSH2_PASS,
        ],
    ]);
    $filename     = 'swoole-sftp-registration-' . getmypid() . '.txt';
    $directoryUrl = sprintf(
        'ssh2.sftp://%s:%d%s',
        TEST_SSH2_HOSTNAME,
        TEST_SSH2_PORT,
        rtrim(TEST_SSH2_TEMPDIR, '/'),
    );
    $fileUrl  = $directoryUrl . '/' . $filename;
    $contents = 'resource-registration';

    var_dump(file_put_contents($fileUrl, $contents, 0, $context) === strlen($contents));
    var_dump(file_get_contents($fileUrl, false, $context) === $contents);

    $directory = opendir($directoryUrl, $context);

    if ($directory === false) {
        throw new RuntimeException('Failed to open the SSH fixture directory.');
    }

    $found = false;

    while (($entry = readdir($directory)) !== false) {
        $found = $found || $entry === $filename;
    }

    closedir($directory);

    var_dump($found);
    var_dump(unlink($fileUrl, $context));

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
