--TEST--
swoole_runtime: hook inherited socket-backed standard streams
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('proc_open');
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

[$process, $stdin, $stdout, $stderr] = start_child('close-read');
$closeRejected = wait_for_line($stderr) === "read-close:no\n";
if ($closeRejected) {
    fwrite($stdin, 'R');
}
fclose($stdin);
$status = read_until_eof($stderr);
read_until_eof($stdout);
$exitCode = proc_close($process);
printf(
    "close during read: %s\n",
    $closeRejected && str_contains($status, "read:R\n") && str_contains($status, "read-final-close:yes\n") &&
        $exitCode === 0
        ? 'yes'
        : 'no'
);

[$process, $stdin, $stdout, $stderr] = start_child('close-write');
$closeRejected = wait_for_line($stderr) === "write-close:no\n";
$output = read_until_eof($stdout);
$status = read_until_eof($stderr);
fclose($stdin);
$exitCode = proc_close($process);
printf(
    "close during write: %s\n",
    $closeRejected && strlen($output) === 1024 * 1024 && str_contains($status, "write-final-close:yes\n") &&
        $exitCode === 0
        ? 'yes'
        : 'no'
);

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
close during read: yes
close during write: yes
concurrent read rejected: yes
concurrent write rejected: yes
