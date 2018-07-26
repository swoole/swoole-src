<?php
if (substr(PHP_OS, 0, 3) == 'WIN')
{
    exit("skip for Windows");
}
if (!extension_loaded("swoole"))
{
    exit("swoole extension is required");
}

function skip(string $reason, bool $is_skip = true)
{
    if ($is_skip) {
        // with yellow color
        exit("skip \033[33m{$reason}\033[0m");
    }
}