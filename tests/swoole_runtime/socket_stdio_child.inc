<?php

function write_all($stream, string $data): void
{
    if (fwrite($stream, $data) !== strlen($data)) {
        exit(1);
    }
}

$scenario = $argv[1] ?? 'default';

if ($scenario === 'modes') {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);
    Co\run(static function (): void {
        stream_set_blocking(STDIN, false);
        $metadata = stream_get_meta_data(STDIN);
        $nonblocking = fread(STDIN, 1) === '' && !feof(STDIN) && !$metadata['blocked'];
        stream_set_blocking(STDIN, true);
        stream_set_timeout(STDIN, 0);
        $zeroTimeout = fread(STDIN, 1) === '' && !stream_get_meta_data(STDIN)['timed_out'] && !feof(STDIN);
        stream_set_blocking(STDOUT, false);
        write_all(STDOUT, "nonblocking\n");
        stream_set_timeout(STDIN, 0, 20000);
        $timedOut = fread(STDIN, 1) === false && stream_get_meta_data(STDIN)['timed_out'];
        write_all(STDOUT, "after timeout\n");
        $writeReady = !stream_get_meta_data(STDOUT)['timed_out'];
        stream_set_blocking(STDOUT, true);
        write_all(STDERR, $nonblocking && $zeroTimeout && $timedOut && $writeReady ? "modes:yes\n" : "modes:no\n");
    });
    stream_set_timeout(STDIN, 2);
    Swoole\Runtime::enableCoroutine(0);
    write_all(STDERR, "disabled\n");
    write_all(STDOUT, 'disabled:' . fgets(STDIN));
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);
    stream_set_timeout(STDIN, 2);
    Co\run(static function (): void {
        go(static function (): void {
            Co::sleep(0.01);
            write_all(STDOUT, "ready\n");
        });
        write_all(STDOUT, 'line:' . fgets(STDIN));
    });
    Co\run(static function (): void {
        $input = fopen('php://fd/0', 'r');
        go(static function (): void {
            Co::sleep(0.01);
            write_all(STDOUT, "ready\n");
        });
        write_all(STDOUT, 'line:' . fgets($input));
        fclose($input);
    });
    write_all(STDERR, "eof-ready\n");
    Co\run(static function (): void {
        $result = fread(STDIN, 1);
        write_all(STDERR, $result === '' && feof(STDIN) ? "eof:yes\n" : "eof:no\n");
    });
    exit;
}

if ($scenario === 'write-timeout') {
    $output = fopen('php://stdout', 'w');
    stream_set_timeout($output, 0, 30000);
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);
    Co\run(static function () use ($output): void {
        go(static function (): void {
            Co::sleep(0.01);
            write_all(STDERR, "tick\n");
        });
        $written = @fwrite($output, str_repeat('A', 4 * 1024 * 1024));
        $metadata = stream_get_meta_data($output);
        write_all(STDERR, $written > 0 && $written < 4 * 1024 * 1024 && $metadata['timed_out']
            ? "write-timeout:yes\n" : "write-timeout:no\n");
    });
    exit;
}

if (str_starts_with($scenario, 'close-')) {
    [, $direction, $owner] = explode('-', $scenario);
    $stream = fopen($direction === 'read' ? 'php://stdin' : 'php://stdout', $direction === 'read' ? 'r' : 'w');
    stream_set_timeout($stream, 2);
    $socket = match ($owner) {
        'native' => socket_import_stream($stream),
        'coroutine' => Swoole\Coroutine\Socket::import($stream),
        default => null,
    };
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

    Co\run(static function () use ($stream, $socket, $direction, $owner): void {
        go(static function () use ($stream, $direction): void {
            $result = $direction === 'read' ? @fread($stream, 1) : @fwrite($stream, str_repeat('A', 1024 * 1024));
            $cancelled = $direction === 'read'
                ? ($result === false || $result === '')
                : is_int($result) && $result > 0 && $result < 1024 * 1024;
            if ($direction === 'write') {
                write_all(STDERR, "written:{$result}\n");
            }
            write_all(STDERR, $cancelled ? "cancelled\n" : "not cancelled\n");
        });
        go(static function () use ($stream, $socket, $owner): void {
            write_all(STDERR, "pending\n");
            match ($owner) {
                'native' => socket_close($socket),
                'coroutine' => $socket->close(),
                default => fclose($stream),
            };
            write_all(STDERR, "closed\n");
        });
    });

    write_all(STDERR, is_resource($stream) ? "resource open\n" : "resource closed\n");
    exit;
}

if ($scenario === 'concurrent-read') {
    stream_set_timeout(STDIN, 5);
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

    Co\run(static function (): void {
        go(static function (): void {
            fread(STDIN, 1);
        });
        go(static function (): void {
            write_all(STDERR, "read-overlap\n");
            stream_set_blocking(STDIN, false);
            fread(STDIN, 1);
        });
    });
    exit;
}

if ($scenario === 'concurrent-write') {
    $output = fopen('php://stdout', 'w');
    stream_set_timeout($output, 5);
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

    Co\run(static function () use ($output): void {
        go(static function () use ($output): void {
            write_all($output, str_repeat('A', 1024 * 1024));
        });
        go(static function () use ($output): void {
            write_all(STDERR, "write-overlap\n");
            // Even the native zero-timeout path must reject overlapping writes.
            stream_set_timeout($output, 0);
            fwrite($output, 'B');
        });
    });
    exit;
}

$output = fopen('php://stdout', 'w');
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

Co\run(static function (): void {
    go(static function (): void {
        Co::sleep(0.01);
        write_all(STDOUT, "ready\n");
    });
    write_all(STDOUT, 'line:' . fgets(STDIN));
});

write_all(STDERR, "reopen\n");
Co\run(static function (): void {
    $input = fopen('php://stdin', 'r');
    go(static function (): void {
        Co::sleep(0.01);
        write_all(STDOUT, "ready\n");
    });
    write_all(STDOUT, 'line:' . fgets($input));
});

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);
write_all(STDERR, "outside\n");
write_all(STDOUT, 'outside:' . fgets(STDIN));

stream_set_timeout(STDIN, 0, 50000);
Co\run(static function (): void {
    $result = fread(STDIN, 1);
    $metadata = stream_get_meta_data(STDIN);
    write_all(STDERR, $result === false && $metadata['timed_out'] ? "timeout\n" : "timeout-failed\n");
});

write_all(STDERR, "backpressure\n");
Co\run(static function () use ($output): void {
    go(static function () use ($output): void {
        write_all($output, str_repeat('A', 1024 * 1024));
        write_all(STDERR, "large-write-done\n");
    });
    go(static function (): void {
        Co::sleep(0.01);
        write_all(STDERR, "second-write-started\n");
        write_all(STDOUT, 'B');
        write_all(STDERR, "second-write-done\n");
    });
    go(static function (): void {
        Co::sleep(0.02);
        write_all(STDERR, "tick\n");
    });
});
