<?php

function http_compression_fixture(): array
{
    $body = '{"ok":true,"message":"compressed JSON"}';
    $encoded = [
        'gzip' => gzencode($body),
        'deflate' => gzcompress($body),
    ];
    if (defined('SWOOLE_HAVE_BROTLI')) {
        // Precomputed Brotli representation of $body; no PHP Brotli extension is required.
        $encoded['br'] = base64_decode('CxOAeyJvayI6dHJ1ZSwibWVzc2FnZSI6ImNvbXByZXNzZWQgSlNPTiJ9Aw==');
    }
    return [$body, $encoded];
}
