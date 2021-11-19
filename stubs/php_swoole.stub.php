<?php

function swoole_version(): string
{
}

function swoole_cpu_num(): int
{
}

function swoole_last_error(): int
{
}

function swoole_async_dns_lookup_coro(mixed $domain_name, float $timeout = 60, int $type = AF_INET): bool
{
}

function swoole_async_set(array $settings): ?bool
{
}

function swoole_coroutine_create(callable $func, mixed ...$params): int|bool
{
}

function swoole_coroutine_defer(callable $callback): ?bool
{
}

function swoole_coroutine_socketpair(int $domain, int $type, int $protocol): array|bool
{
}

function swoole_test_kernel_coroutine(int $count = 100, float $sleep_time = 1.0): ?bool
{
}

function swoole_client_select(array &$read_array, array &$write_array, array &$error_array, float $timeout = 0.5): bool|int
{
}

function swoole_set_process_name(string $process_name): bool
{
}

function swoole_get_local_ip(): bool|array
{
}

function swoole_get_local_mac(): bool|array
{
}

function swoole_strerror(int $errno, int $error_type = SWOOLE_STRERROR_SYSTEM): string
{
}

function swoole_errno(): int
{
}

function swoole_clear_error(): void
{
}

function swoole_error_log(int $level, string $msg): ?bool
{
}

function swoole_error_log_ex(int $level, int $error, string $msg): ?bool
{
}

function swoole_ignore_error(int $error): ?bool
{
}

function swoole_hashcode(string $data, int $type = 0): bool|int
{
}

function swoole_mime_type_add(string $suffix, string $mime_type): bool
{
}

function swoole_mime_type_set(string $suffix, string $mime_type): ?bool
{
}

function swoole_mime_type_delete(string $suffix): bool
{
}

function swoole_mime_type_get(string $filename): string
{
}

function swoole_mime_type_exists(string $filename): bool
{
}

function swoole_mime_type_list(): array
{
}

function swoole_clear_dns_cache(): void
{
}

function swoole_substr_unserialize(string $str, int $offset, int $length = 0, array $options = []): mixed
{
}

function swoole_substr_json_decode(string $str, int $offset, int $length = 0, bool $associative = false, int $depth = 512, int $flags = 0): mixed
{
}

function swoole_internal_call_user_shutdown_begin(): bool
{
}
