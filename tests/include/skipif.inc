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
        exit("skip {$reason}");
    }
}