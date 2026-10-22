<?php

function write_all($stream, string $data): void
{
    if (fwrite($stream, $data) !== strlen($data)) {
        exit(1);
    }
}

$scenario = $argv[1] ?? 'default';

if ($scenario === 'close-read') {
    $input = fopen('php://stdin', 'r');
    stream_set_timeout($input, 5);
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

    Co\run(static function () use ($input): void {
        go(static function () use ($input): void {
            write_all(STDERR, 'read:' . fread($input, 1) . "\n");
        });
        go(static function () use ($input): void {
            write_all(STDERR, @fclose($input) ? "read-close:yes\n" : "read-close:no\n");
        });
    });

    write_all(STDERR, fclose($input) ? "read-final-close:yes\n" : "read-final-close:no\n");
    exit;
}

if ($scenario === 'close-write') {
    $output = fopen('php://stdout', 'w');
    stream_set_timeout($output, 5);
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_STDIO);

    Co\run(static function () use ($output): void {
        go(static function () use ($output): void {
            write_all($output, str_repeat('A', 1024 * 1024));
        });
        go(static function () use ($output): void {
            write_all(STDERR, @fclose($output) ? "write-close:yes\n" : "write-close:no\n");
        });
    });

    write_all(STDERR, fclose($output) ? "write-final-close:yes\n" : "write-final-close:no\n");
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
