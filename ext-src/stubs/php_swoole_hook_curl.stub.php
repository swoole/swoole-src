<?php

/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

function swoole_hook_curl_init(?string $url = null): Swoole\Curl\Handler|false
{

}

function swoole_hook_curl_setopt(Swoole\Curl\Handler $obj, int $opt, mixed $value): bool
{

}

function swoole_hook_curl_setopt_array(Swoole\Curl\Handler $obj, array $array): bool
{
}

function swoole_hook_curl_exec(Swoole\Curl\Handler $obj): string|bool
{

}

function swoole_hook_curl_getinfo(Swoole\Curl\Handler $obj, int $opt = 0): mixed
{

}

function swoole_hook_curl_errno(Swoole\Curl\Handler $obj): int
{

}

function swoole_hook_curl_error(Swoole\Curl\Handler $obj): string
{

}

function swoole_hook_curl_reset(Swoole\Curl\Handler $obj): void
{

}

function swoole_hook_curl_close(Swoole\Curl\Handler $obj): void
{

}

function swoole_hook_curl_multi_getcontent(Swoole\Curl\Handler $obj): ?string
{

}
