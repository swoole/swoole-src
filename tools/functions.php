#!/usr/bin/env php
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

function swoole_log(string $content, int $color = 0)
{
    echo ($color ? "\033[3{$color}m{$content}\033[0m" : $content) . "\n";

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
    echo "========== Execute Script ==========\n";
    exec($command, $output, $return_var);
    echo '> ' . implode("\n> ", $output) . "\n";
    if ($return_var != 0) {
        swoole_error("Exec {$command} failed with code {$return_var}!");
    }
    echo "=========== Finish Done ============\n\n";
}

function scan_dir(string $dir, callable $filter = null): array
{
    $files = array_filter(scandir($dir), function (string $f) {
        return $f{0} !== '.';
    });
    return array_values($filter ? array_filter($files, $filter) : $files);
}

function swoole_git_files(): array
{
    $root = SWOOLE_SOURCE_ROOT;
    return explode("\n", `cd {$root} && git ls-files`);
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
