--TEST--
swoole_runtime: hook inherited socket-backed standard streams
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
skip_if_function_not_exist('socket_import_stream');
?>
--FILE--
<?php
function wait_for_line($stream): string|false
{
    $read = [$stream];
    $write = null;
    $except = null;
    if (stream_select($read, $write, $except, 1) !== 1) {
        return false;
    }
    return fgets($stream);
}

function test_partial_line($input, $output, string $line): bool
{
    fwrite($input, $line);
    $first = wait_for_line($output);
    $progressed = $first === "ready\n";
    fwrite($input, "\n");

    $lines = $first === false ? [] : [$first];
    while (count($lines) < 2 && ($next = wait_for_line($output)) !== false) {
        $lines[] = $next;
    }

    sort($lines);
    return $progressed && $lines === ["line:{$line}\n", "ready\n"];
}

function read_until_eof($stream): string
{
    $result = '';
    $deadline = microtime(true) + 5;
    while (!feof($stream) && microtime(true) < $deadline) {
        $read = [$stream];
        $write = null;
        $except = null;
        if (stream_select($read, $write, $except, 0, 200000) === 1) {
            $result .= fread($stream, 8192);
        }
    }
    return $result;
}

function start_child(string $scenario): array
{
    [$stdin, $childStdin] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$stdout, $childStdout] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
    [$stderr, $childStderr] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);

    $command = sprintf(
        'exec %s %s %s %s',
        escapeshellarg(PHP_BINARY),
        getenv('TEST_PHP_EXTRA_ARGS'),
        escapeshellarg(__DIR__ . '/socket_stdio_child.inc'),
        escapeshellarg($scenario)
    );
    $process = proc_open($command, [$childStdin, $childStdout, $childStderr], $pipes);
    fclose($childStdin);
    fclose($childStdout);
    fclose($childStderr);

    return [$process, $stdin, $stdout, $stderr];
}

[$process, $stdin, $stdout, $stderr] = start_child('default');

printf("stdin: %s\n", test_partial_line($stdin, $stdout, 'first') ? 'yes' : 'no');
$reopened = wait_for_line($stderr) === "reopen\n" && test_partial_line($stdin, $stdout, 'second');
printf("reopened stdin: %s\n", $reopened ? 'yes' : 'no');

$outside = wait_for_line($stderr) === "outside\n";
fwrite($stdin, "third\n");
printf("outside coroutine: %s\n", $outside && wait_for_line($stdout) === "outside:third\n" ? 'yes' : 'no');
printf("timeout: %s\n", wait_for_line($stderr) === "timeout\n" ? 'yes' : 'no');

$backpressure = wait_for_line($stderr) === "backpressure\n";
$status = '';
for ($i = 0; $i < 3 && !str_contains($status, "tick\n"); $i++) {
    $line = wait_for_line($stderr);
    if ($line === false) {
        break;
    }
    $status .= $line;
}
printf("stdout progress: %s\n", $backpressure && str_contains($status, "tick\n") ? 'yes' : 'no');

$output = read_until_eof($stdout);
$exitCode = proc_close($process);
printf(
    "stdout data: %s\n",
    strlen($output) === 1024 * 1024 + 1 && substr_count($output, 'A') === 1024 * 1024 && substr_count($output, 'B') === 1
        ? 'yes'
        : 'no'
);
printf("exit: %d\n", $exitCode);

[$process, $stdin, $stdout, $stderr] = start_child('modes');
$mode = wait_for_line($stderr) === "modes:yes\n";
$nonblockingWrite = wait_for_line($stdout) === "nonblocking\n" && wait_for_line($stdout) === "after timeout\n";
printf("stream modes: %s\n", $mode && $nonblockingWrite ? 'yes' : 'no');
$disabled = wait_for_line($stderr) === "disabled\n";
fwrite($stdin, "native\n");
printf("hooks disabled: %s\n", $disabled && wait_for_line($stdout) === "disabled:native\n" ? 'yes' : 'no');
printf("hooks reenabled: %s\n", test_partial_line($stdin, $stdout, 'enabled') ? 'yes' : 'no');
printf("php fd stream: %s\n", test_partial_line($stdin, $stdout, 'fd') ? 'yes' : 'no');
$eofReady = wait_for_line($stderr) === "eof-ready\n";
// proc_open may also inherit a duplicate of the parent's endpoint; explicitly send EOF.
stream_socket_shutdown($stdin, STREAM_SHUT_WR);
fclose($stdin);
printf("eof: %s\n", $eofReady && wait_for_line($stderr) === "eof:yes\n" ? 'yes' : 'no');
read_until_eof($stdout);
printf("modes exit: %d\n", proc_close($process));

[$process, $stdin, $stdout, $stderr] = start_child('write-timeout');
$tick = wait_for_line($stderr) === "tick\n";
$timedOut = wait_for_line($stderr) === "write-timeout:yes\n";
$output = read_until_eof($stdout);
fclose($stdin);
printf("write timeout: %s\n", $tick && $timedOut && strlen($output) > 0 && proc_close($process) === 0 ? 'yes' : 'no');

foreach (['stream', 'native', 'coroutine'] as $owner) {
    foreach (['read', 'write'] as $direction) {
        [$process, $stdin, $stdout, $stderr] = start_child("close-{$direction}-{$owner}");
        $pending = wait_for_line($stderr) === "pending\n";
        $output = read_until_eof($stdout);
        $status = read_until_eof($stderr);
        fclose($stdin);
        $exitCode = proc_close($process);
        $partialWrite = $direction === 'read' ||
            (strlen($output) > 0 && strlen($output) < 1024 * 1024 && substr_count($output, 'A') === strlen($output));
        printf(
            "close %s during %s: %s\n",
            $owner,
            $direction,
            $pending && str_contains($status, "cancelled\n") && str_contains($status, "closed\n") &&
                str_contains($status, "resource closed\n") && $partialWrite && $exitCode === 0 ? 'yes' : 'no'
        );
    }
}

[$process, $stdin, $stdout, $stderr] = start_child('concurrent-read');
$started = wait_for_line($stderr) === "read-overlap\n";
fclose($stdin);
$status = read_until_eof($stderr);
$output = read_until_eof($stdout);
proc_close($process);
printf(
    "concurrent read rejected: %s\n",
    $started && str_contains($status . $output, 'reading of the same socket') ? 'yes' : 'no'
);

[$process, $stdin, $stdout, $stderr] = start_child('concurrent-write');
$started = wait_for_line($stderr) === "write-overlap\n";
$output = read_until_eof($stdout);
$status = read_until_eof($stderr);
fclose($stdin);
proc_close($process);
printf(
    "concurrent write rejected: %s\n",
    $started && str_contains($status . $output, 'writing of the same socket') ? 'yes' : 'no'
);
?>
--EXPECT--
stdin: yes
reopened stdin: yes
outside coroutine: yes
timeout: yes
stdout progress: yes
stdout data: yes
exit: 0
stream modes: yes
hooks disabled: yes
hooks reenabled: yes
php fd stream: yes
eof: yes
modes exit: 0
write timeout: yes
close stream during read: yes
close stream during write: yes
close native during read: yes
close native during write: yes
close coroutine during read: yes
close coroutine during write: yes
concurrent read rejected: yes
concurrent write rejected: yes
