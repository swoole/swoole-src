--TEST--
Direct SFTP wrapper authentication failures release their native sessions
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();

if (!is_dir('/proc/self/fd')) {
    echo 'skip requires /proc/self/fd';
}
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $context = stream_context_create([
        'ssh2' => [
            'username' => TEST_SSH2_USER,
            'password' => 'invalid-swoole-test-password',
        ],
    ]);
    $url = sprintf(
        'ssh2.sftp://%s:%d%s/missing.txt',
        TEST_SSH2_HOSTNAME,
        TEST_SSH2_PORT,
        rtrim(TEST_SSH2_TEMPDIR, '/'),
    );
    $fileDescriptorCount = static fn (): int => count(scandir('/proc/self/fd')) - 2;

    $warmupFailed = @fopen($url, 'rb', false, $context) === false;
    $baseline     = $fileDescriptorCount();

    // Keep the two failures below OpenSSH 9.8+'s default per-source penalty floor
    // so this test cannot block later tests that share the SSH server.
    $attemptFailed = @fopen($url, 'rb', false, $context) === false;

    gc_collect_cycles();

    var_dump($warmupFailed);
    var_dump($attemptFailed);
    var_dump($fileDescriptorCount() === $baseline);
});
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
