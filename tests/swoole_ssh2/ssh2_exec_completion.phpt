--TEST--
SSH2 exec streams publish completion only after the remote command exits
--SKIPIF--
<?php
require_once 'ssh2_skip.inc';
ssh2t_needs_auth();
?>
--FILE--
<?php
require __DIR__ . '/ssh2_test.inc';

Co\run(function (): void {
    $session = ssh2_connect(TEST_SSH2_HOSTNAME, TEST_SSH2_PORT);

    if ($session === false || !ssh2t_auth($session)) {
        throw new RuntimeException('Failed to connect to the SSH fixture.');
    }

    $startedAt = microtime(true);
    $blocking = ssh2_exec($session, "printf blocking; exec 1>&- 2>&-; sleep 1; exit 7");

    if ($blocking === false) {
        throw new RuntimeException('Failed to open the blocking exec channel.');
    }

    var_dump(stream_get_contents($blocking));
    var_dump(microtime(true) - $startedAt >= 0.5);
    var_dump(stream_get_meta_data($blocking)['exit_status']);

    $nonblocking = ssh2_exec(
        $session,
        "printf stdout; printf stderr >&2; exec 1>&- 2>&-; sleep 1; exit 7",
    );

    if ($nonblocking === false) {
        throw new RuntimeException('Failed to open the nonblocking exec channel.');
    }

    $stderr = ssh2_fetch_stream($nonblocking, SSH2_STREAM_STDERR);

    if ($stderr === false) {
        throw new RuntimeException('Failed to open the stderr stream.');
    }

    stream_set_blocking($nonblocking, false);
    stream_set_blocking($stderr, false);
    var_dump(stream_set_read_buffer($nonblocking, 0));

    $stdoutContents = '';
    $stderrContents = '';
    $deadline = microtime(true) + 5;

    while (!feof($nonblocking) || !feof($stderr)) {
        if (!feof($nonblocking)) {
            $chunk = fread($nonblocking, 8192);
            if ($chunk === false) {
                throw new RuntimeException('Failed to read stdout.');
            }
            $stdoutContents .= $chunk;
        }
        if (!feof($stderr)) {
            $chunk = fread($stderr, 8192);
            if ($chunk === false) {
                throw new RuntimeException('Failed to read stderr.');
            }
            $stderrContents .= $chunk;
        }
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('Timed out draining the nonblocking exec channel.');
        }
        Co::sleep(0.001);
    }

    var_dump($stdoutContents);
    var_dump($stderrContents);
    var_dump(stream_get_meta_data($nonblocking)['exit_status']);

    $pty = ssh2_exec($session, 'sleep 0.1; exit 7', 'xterm');

    if ($pty === false) {
        throw new RuntimeException('Failed to open the PTY exec channel.');
    }

    stream_get_contents($pty);
    var_dump(stream_get_meta_data($pty)['exit_status']);

    $successful = ssh2_exec($session, 'exit 0');

    if ($successful === false) {
        throw new RuntimeException('Failed to open the successful exec channel.');
    }

    stream_get_contents($successful);
    $metadata = stream_get_meta_data($successful);
    var_dump($metadata['exit_status']);
    var_dump($metadata['exit_signal']);

    fclose($blocking);
    fclose($stderr);
    fclose($nonblocking);
    fclose($pty);
    fclose($successful);
    ssh2_disconnect($session);
});
?>
--EXPECT--
string(8) "blocking"
bool(true)
int(7)
int(0)
string(6) "stdout"
string(6) "stderr"
int(7)
int(7)
int(0)
NULL
