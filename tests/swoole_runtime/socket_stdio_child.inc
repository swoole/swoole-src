<?php

function write_all($stream, string $data): void
{
    if (fwrite($stream, $data) !== strlen($data)) {
        exit(1);
    }
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
