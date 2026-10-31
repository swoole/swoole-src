--TEST--
ssh2_scp_recv() reports failed and incomplete local writes
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
ssh2t_writes_remote();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

class FailingScpWriteStream
{
    public $context;

    public static bool $shortWrite = false;

    private bool $wrote = false;

    public function stream_open($path, $mode, $options, &$openedPath): bool
    {
        return true;
    }

    public function stream_write($data)
    {
        if (!self::$shortWrite || $this->wrote) {
            return false;
        }

        // PHP retries positive partial writes, so fail the next call to expose the short total.
        $this->wrote = true;

        return 1;
    }

    public function stream_close(): void
    {
    }
}

if (!stream_wrapper_register('scpwritefail', FailingScpWriteStream::class)) {
    throw new RuntimeException('Failed to register the local write fixture.');
}

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);
    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $remoteFile = ssh2t_tempnam();
    $remoteContent = 'This is test content for SCP receive';
    $sftp = ssh2_sftp($session);
    $stream = $sftp === false ? false : fopen("ssh2.sftp://{$sftp}/{$remoteFile}", 'w');
    if ($stream === false || fwrite($stream, $remoteContent) !== strlen($remoteContent)) {
        throw new RuntimeException('Failed to create the remote SCP fixture.');
    }
    fclose($stream);

    var_dump(ssh2_scp_recv($session, $remoteFile, 'scpwritefail://failure') === false);

    FailingScpWriteStream::$shortWrite = true;
    var_dump(ssh2_scp_recv($session, $remoteFile, 'scpwritefail://short') === false);

    ssh2_sftp_unlink($sftp, $remoteFile);
    ssh2_disconnect($session);
});

stream_wrapper_unregister('scpwritefail');
?>
--EXPECTF--
Warning: ssh2_scp_recv(): Error writing to local file in %s on line %d
bool(true)

Warning: ssh2_scp_recv(): Mismatch in bytes read from remote file and bytes written to local file in %s on line %d
bool(true)
