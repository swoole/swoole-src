<?php
define('EMOJI_OK', '✅');
define('EMOJI_SUCCESS', '🚀');
define('EMOJI_ERROR', '❌');
define('EMOJI_WARN', '⚠️');
define('SWOOLE_SOURCE_ROOT', dirname(__DIR__) . '/');
define('SWOOLE_COLOR_RED', 1);
define('SWOOLE_COLOR_GREEN', 2);
define('SWOOLE_COLOR_YELLOW', 3);
define('SWOOLE_COLOR_BLUE', 4);
define('SWOOLE_COLOR_MAGENTA', 5);
define('SWOOLE_COLOR_CYAN', 6);
define('SWOOLE_COLOR_WHITE', 7);

function space(int $length): string
{
    return str_repeat(' ', $length);
}

function camelize(string $uncamelized_words, string $separator = '_'): string
{
    $uncamelized_words = $separator . str_replace($separator, " ", strtolower($uncamelized_words));
    return ltrim(str_replace(" ", "", ucwords($uncamelized_words)), $separator);
}

function unCamelize(string $camelCaps, string $separator = '_'): string
{
    return strtolower(preg_replace('/([a-z])([A-Z])/', "$1" . $separator . "$2", $camelCaps));
}

function print_split_line(string $title = '', int $length = 32)
{
    if ($length % 2 !== 0) {
        $length += 1;
    }
    echo "< {$title} > " . str_repeat('=', $length) . PHP_EOL;
}

function swoole_log(string $content, int $color = 0)
{
    echo ($color ? "\033[3{$color}m{$content}\033[0m" : $content) . PHP_EOL;
}

function swoole_check(bool $is_ok, string $output)
{
    if ($is_ok) {
        swoole_ok("{$output} OK!");
    } else {
        swoole_error("{$output} Failed!");
    }
}

function swoole_warn(string ...$args)
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_WARN . " {$arg}", SWOOLE_COLOR_YELLOW);
    }
}

function swoole_error(string ...$args)
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_ERROR . " {$arg}", SWOOLE_COLOR_RED);
    }
    exit(255);
}

function swoole_ok(string ...$args)
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_OK . " {$arg}", SWOOLE_COLOR_GREEN);
    }
}

function swoole_success(string $content)
{
    swoole_log(
        str_repeat(EMOJI_SUCCESS, 3) . $content . str_repeat(EMOJI_SUCCESS, 3),
        SWOOLE_COLOR_CYAN
    );
    exit(0);
}

function swoole_execute_and_check(string $command)
{
    $basename = pathinfo(explode(' ', $command)[1], PATHINFO_FILENAME);
    echo "[{$basename}]" . PHP_EOL;
    echo "===========  Execute  ==============" . PHP_EOL;
    exec($command, $output, $return_var);
    if (substr($output[0] ?? '', 0, 2) === '#!') {
        array_shift($output);
    }
    echo '> ' . implode("\n> ", $output) . "" . PHP_EOL;
    if ($return_var != 0) {
        swoole_error("Exec {$command} failed with code {$return_var}!");
    }
    echo "=========== Finish Done ============" . PHP_EOL . PHP_EOL;
}

function scan_dir(string $dir, callable $filter = null): array
{
    $files = array_filter(scandir($dir), function (string $file) { return $file[0] !== '.'; });
    array_walk($files, function (&$file) use ($dir) { $file = "{$dir}/{$file}"; });
    return array_values($filter ? array_filter($files, $filter) : $files);
}

function file_size(string $filename, int $decimals = 2)
{
    $bytes = filesize($filename);
    $sz = 'BKMGTP';
    $factor = (int)floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . $sz[$factor];
}

function swoole_git_files(): array
{
    $root = SWOOLE_SOURCE_ROOT;
    return explode(PHP_EOL, `cd {$root} && git ls-files`);
}

function swoole_source_list(array $ext_list = [], array $excepts = []): array
{
    $source_list = swoole_git_files();
    $source_list = array_filter($source_list, function (string $filename) use ($ext_list, $excepts) {
        $ext_list = $ext_list + [
                'h' => true,
                'c' => true,
                'cc' => true
            ];
        $excepts = $excepts + [
                'core-tests',
                'examples',
                'thirdparty'
            ];
        foreach ($excepts as $except) {
            if (preg_match("/{$except}/", $filename)) {
                return false;
            }
        }
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        return $ext_list[$ext] ?? false;
    });
    sort($source_list);

    return $source_list;
}
