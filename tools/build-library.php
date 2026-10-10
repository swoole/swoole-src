#!/usr/bin/env php
<?php
if (isset($argv[1]) and $argv[1] == 'dev') {
    putenv('SWOOLE_LIBRARY_DEV=1');
}
$root = realpath(__DIR__ . '/..');
putenv('SWOOLE_DIR=' . $root);

// The upstream command exits on success, so run it separately before escaping its output.
$process = proc_open([
    PHP_BINARY, '-n', __DIR__ . '/vendor/bin/make-library.php', realpath($root . '/library/src'),
], [STDIN, STDOUT, STDERR], $pipes);
if (!is_resource($process)) {
    fwrite(STDERR, "Unable to start the library generator\n");
    exit(1);
}
$status = proc_close($process);
if ($status !== 0) {
    exit($status);
}

$output = $root . '/ext-src/php_swoole_library.h';
$header = file_get_contents($output);
if ($header === false) {
    fwrite(STDERR, "Unable to read the generated library header\n");
    exit(1);
}

// C++14 replaces trigraphs before parsing string literals. Escaping the second question mark
// prevents that replacement, while the compiled string still contains the original PHP bytes.
$escaped = preg_replace_callback('/\?\?(?=[=\/\'()!<>-])/', static fn () => '?\\?', $header);
if ($escaped !== $header && file_put_contents($output, $escaped) !== strlen($escaped)) {
    fwrite(STDERR, "Unable to write the escaped library header\n");
    exit(1);
}
