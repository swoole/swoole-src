<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

function swoole_call_array_method(mixed ...$args): mixed {}

function swoole_call_string_method(mixed ...$args): mixed {}

function swoole_call_stream_method(mixed ...$args): mixed {}

function swoole_array_search(array $array, mixed $value, bool $strict = false): false|int|string {}

function swoole_array_contains(array $array, mixed $needle, bool $strict = false): bool {}

function swoole_array_join(array $array, string $separator): string {}

function swoole_array_key_exists(array $array, null|bool|float|int|resource|string $key): bool {}

function swoole_array_map(array $array, ?callable $callback, array ...$arrays): array {}

function swoole_array_is_typed(array $array, string $typeDef = ''): bool {}

function swoole_array_is_empty(array $array): bool {}

function swoole_str_split(string $string, string $delimiter, int $limit = PHP_INT_MAX): array {}

function swoole_str_is_empty(string $string): bool {}

function swoole_str_match(string $string, string $pattern, int $flags = 0, int $offset = 0): array|false {}

function swoole_str_match_all(string $string, string $pattern, int $flags = 0, int $offset = 0): array|false {}

function swoole_str_json_decode(string $string, int $depth = 512, int $flags = 0): mixed {};

function swoole_str_json_decode_to_object(string $string, int $depth = 512, int $flags = 0): mixed {};

function swoole_parse_str(string $string): array {}

function swoole_hash(string $data, string $algo, bool $binary = false, array $options = []): string {}

function swoole_typed_array(string $typeDef, ?array $initArray = null): array {}

function swoole_str_replace(string $subject, array|string $search, array|string $replace): string {}

function swoole_str_ireplace(string $subject, array|string $search, array|string $replace): string {}

function swoole_array_replace_str(array $subjects, array|string $search, array|string $replace): array {}

function swoole_array_ireplace_str(array $subjects, array|string $search, array|string $replace): array {}
