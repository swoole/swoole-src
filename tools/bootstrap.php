<?php
/**
 * This file is part of Swoole, for internal use only
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/swoole-src/blob/master/LICENSE
 */

define('ROOT_DIR', dirname(__DIR__));
const LIBRARY_DIR = ROOT_DIR . '/library';
const LIBRARY_SRC_DIR = LIBRARY_DIR . '/src';
const PHP_TAG = '<?php';

if (!defined('EMOJI_OK')) {
    define('EMOJI_OK', '✅');
}
if (!defined('EMOJI_SUCCESS')) {
    define('EMOJI_SUCCESS', '🚀');
}
if (!defined('EMOJI_ERROR')) {
    define('EMOJI_ERROR', '❌');
}
if (!defined('EMOJI_WARN')) {
    define('EMOJI_WARN', '⚠️');
}

define('SWOOLE_SOURCE_ROOT', dirname(__DIR__) . '/');

if (!defined('SWOOLE_COLOR_RED')) {
    define('SWOOLE_COLOR_RED', 1);
    define('SWOOLE_COLOR_GREEN', 2);
    define('SWOOLE_COLOR_YELLOW', 3);
    define('SWOOLE_COLOR_BLUE', 4);
    define('SWOOLE_COLOR_MAGENTA', 5);
    define('SWOOLE_COLOR_CYAN', 6);
    define('SWOOLE_COLOR_WHITE', 7);
}

function space(int $length): string
{
    return str_repeat(' ', $length);
}

function camelize(string $uncamelized_words, string $separator = '_'): string
{
    $uncamelized_words = $separator . str_replace($separator, ' ', strtolower($uncamelized_words));
    return ltrim(str_replace(' ', '', ucwords($uncamelized_words)), $separator);
}

function unCamelize(string $camelCaps, string $separator = '_'): string
{
    $camelCaps = preg_replace('/([a-z])([A-Z])/', "\${1}{$separator}\${2}", $camelCaps);
    /* for special case like: PDOPool => pdo_pool */
    $camelCaps = preg_replace('/([A-Z]+)([A-Z][a-z]+)/', "\${1}{$separator}\${2}\${3}", $camelCaps);
    return strtolower($camelCaps);
}

function print_split_line(string $title = '', int $length = 32): void
{
    if ($length % 2 !== 0) {
        $length += 1;
    }
    echo "< {$title} > " . str_repeat('=', $length) . PHP_EOL;
}

function swoole_log(string $content, int $color = 0): void
{
    echo ($color ? "\033[3{$color}m{$content}\033[0m" : $content) . PHP_EOL;
}

function swoole_check(bool $is_ok, string $output): void
{
    if ($is_ok) {
        swoole_ok("{$output} OK!");
    } else {
        swoole_error("{$output} Failed!");
    }
}

function swoole_warn(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_WARN . " {$arg}", SWOOLE_COLOR_YELLOW);
    }
}

function swoole_error(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_ERROR . " {$arg}", SWOOLE_COLOR_RED);
    }
    exit(255);
}

function swoole_ok(string ...$args): void
{
    foreach ($args as $arg) {
        swoole_log(EMOJI_OK . " {$arg}", SWOOLE_COLOR_GREEN);
    }
}

function swoole_success(string $content): void
{
    swoole_log(
        str_repeat(EMOJI_SUCCESS, 3) . $content . str_repeat(EMOJI_SUCCESS, 3),
        SWOOLE_COLOR_CYAN
    );
    exit(0);
}

function swoole_execute_and_check(array $commands): void
{
    $basename = pathinfo($commands[1] ?? '', PATHINFO_FILENAME);
    echo "[{$basename}]" . PHP_EOL;
    echo "===========  Execute  ==============" . PHP_EOL;
    $command = implode(' ', $commands);
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
    $files = array_filter(scandir($dir), function (string $file) {
        return $file[0] !== '.';
    });
    array_walk($files, function (&$file) use ($dir) {
        $file = "{$dir}/{$file}";
    });
    return array_values($filter ? array_filter($files, $filter) : $files);
}

function scan_dir_recursive(string $dir, callable $filter = null): array
{
    $result = [];
    $files = scan_dir($dir, $filter);
    foreach ($files as $f) {
        if (is_dir($f)) {
            $result = array_merge($result, scan_dir_recursive($f, $filter));
        } else {
            $result[] = $f;
        }
    }
    return $result;
}

function file_size(string $filename, int $decimals = 2): string
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
                'tools',
                'thirdparty',
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

function swoole_library_files($librarySrcDir)
{
    $files = [];

    $file_spl_objects = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($librarySrcDir, \RecursiveDirectoryIterator::SKIP_DOTS),
        \RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($file_spl_objects as $full_file_name => $file_spl_object) {
        $files[] = str_replace($librarySrcDir . '/', '', $full_file_name);
    }

    return $files;
}

function swoole_remove_php_comments($code)
{
    $newCode = '';
    $commentTokens = [T_COMMENT];

    if (defined('T_DOC_COMMENT')) {
        $commentTokens[] = T_DOC_COMMENT;
    }

    if (defined('T_ML_COMMENT')) {
        $commentTokens[] = T_ML_COMMENT;
    }

    $tokens = token_get_all($code);
    foreach ($tokens as $token) {
        if (is_array($token)) {
            if (in_array($token[0], $commentTokens)) {
                continue;
            }
            $token = $token[1];
        }
        $newCode .= $token;
    }

    return $newCode;
}

class SwooleLibraryBuilder
{
    public $checkFileChange;
    public $libraryDir;
    public $librarySrcDir;
    public $files;
    public $srcPath;
    public $stripComments = true;
    public $symbolPrefix = 'swoole';
    public $outputFile;

    function make()
    {
        if ($this->checkFileChange) {
            preg_match(
                '/^(\d+)/',
                trim(shell_exec('cd ' . $this->libraryDir . ' && git diff --shortstat')),
                $file_change
            );
            $file_change = (int)($file_change[1] ?? 0);
            if ($file_change > 0) {
                swoole_error($file_change . ' file changed in [' . $this->libraryDir . ']');
            }
        }

        $commit_id = trim(shell_exec('cd ' . $this->libraryDir . ' && git rev-parse HEAD'));
        if (!$commit_id || strlen($commit_id) != 40) {
            swoole_error('Unable to get commit id of library in [' . $this->libraryDir . ']');
        }

        $ignore_files = ['vendor_init.php',];

        $diff_files = array_diff(swoole_library_files($this->librarySrcDir), $this->files);
        foreach ($diff_files as $k => $f) {
            if (in_array($f, $ignore_files)) {
                unset($diff_files[$k]);
            }
        }

        if (!empty($diff_files)) {
            swoole_error('Some files are not loaded: ', ...$diff_files);
        }

        foreach ($this->files as $file) {
            if (!file_exists($this->librarySrcDir . '/' . $file)) {
                swoole_error("Unable to find source file [{$file}]");
            }
        }

        $source_str = $eval_str = '';
        foreach ($this->files as $file) {
            $php_file = $this->librarySrcDir . '/' . $file;
            if (strpos(`/usr/bin/env php -n -l {$php_file} 2>&1`, 'No syntax errors detected') === false) {
                swoole_error("Syntax error in file [{$php_file}]");
            } else {
                swoole_ok("Syntax correct in [{$file}]");
            }
            $code = file_get_contents($php_file);
            if ($code === false) {
                swoole_error("Can not read file [{$file}]");
            }
            if (strpos($code, PHP_TAG) !== 0) {
                swoole_error("File [{$file}] must start with \"<?php\"");
            }
            if ($this->stripComments) {
                $code = swoole_remove_php_comments($code);
            }
            $name = unCamelize(str_replace(['/', '.php'], ['_', ''], $file));
            // keep line breaks to align line numbers
            $code = rtrim(substr($code, strlen(PHP_TAG)));
            $code = str_replace(['\\', '"', "\n"], ['\\\\', '\\"', "\\n\"\n\""], $code);
            $code = implode("\n" . space(4), explode("\n", $code));
            $filename = "{$this->srcPath}/{$file}";
            $source_str .= "static const char* {$this->symbolPrefix}_library_source_{$name} =\n" . space(4) . "\"{$code}\\n\";\n\n";
            $eval_str .= space(4) . "zend::eval({$this->symbolPrefix}_library_source_{$name}, \"{$filename}\");\n";
        }
        $source_str = rtrim($source_str);
        $eval_str = rtrim($eval_str);

        global $argv;
        $generator = basename($argv[0]);
        $content = <<<CODE
/**
 * -----------------------------------------------------------------------
 * Generated by {$generator}, Please DO NOT modify!
  +----------------------------------------------------------------------+
  | Swoole                                                               |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
 */

/* \$Id: {$commit_id} */

{$source_str}

void php_{$this->symbolPrefix}_load_library()
{
{$eval_str}
}

CODE;

        if (file_put_contents($this->outputFile, $content) != strlen($content)) {
            swoole_error('Can not write source codes to ' . $this->outputFile);
        }
        swoole_success("Generated swoole php library successfully!");
    }
}
