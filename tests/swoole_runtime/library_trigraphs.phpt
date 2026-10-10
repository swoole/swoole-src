--TEST--
swoole_runtime: generated library preserves null-coalescing assignment and all C++ trigraphs
--SKIPIF--
<?php
if (PHP_OS_FAMILY === 'Windows') die('skip requires Unix symlinks and a C++ compiler');
if (!function_exists('proc_open') || !function_exists('exec')) die('skip requires process execution');
if (!is_file(__DIR__ . '/../../tools/vendor/bin/make-library.php')) die('skip requires tools Composer dependencies');
exec('command -v c++', $output, $status);
if ($status !== 0) die('skip requires a C++ compiler');
exec('command -v git', $output, $status);
if ($status !== 0) die('skip requires git');
?>
--FILE--
<?php
require __DIR__ . '/../include/lib/src/Assert.php';

use SwooleTest\Assert;

function library_trigraphs_run(array $command): string
{
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Failed to start test command');
    }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    if (proc_close($process) !== 0) {
        throw new RuntimeException('Test command failed: ' . $output);
    }
    return $output;
}

$root = dirname(__DIR__, 2);
$directory = sys_get_temp_dir() . '/swoole-library-trigraphs-' . bin2hex(random_bytes(8));
mkdir($directory);
try {
    mkdir($directory . '/tools');
    mkdir($directory . '/ext-src');
    mkdir($directory . '/library');
    mkdir($directory . '/library/src');
    copy($root . '/tools/build-library.php', $directory . '/tools/build-library.php');
    symlink($root . '/tools/vendor', $directory . '/tools/vendor');
    library_trigraphs_run(['git', 'init', '-q', '--template=', $directory . '/library']);
    library_trigraphs_run([
        'git', '-C', $directory . '/library', '-c', 'user.name=Library Test',
        '-c', 'user.email=library-test@example.com', '-c', 'commit.gpgsign=false',
        'commit', '--allow-empty', '-qm', 'Test fixture',
    ]);
    file_put_contents($directory . '/library/src/__init__.php', <<<'PHP'
<?php
return [
    'name' => 'swoole',
    'output' => getenv('SWOOLE_DIR') . '/ext-src/php_swoole_library.h',
    'checkFileChange' => false,
    'stripComments' => false,
    'files' => ['fixture.php'],
];
PHP);
    $source = <<<'PHP'
<?php
/* Preserve trigraphs in comments too: ??= ??/ ??' ??( ??) ??! ??< ??> ??- */
$values = [];
$values['existing'] ??= 'first';
$values['existing'] ??= 'second';
$values['nested']['value'] ??= 'nested';
$values['null'] = null;
$values['null'] ??= 'fallback';
$text = <<<'TEXT'
??= ??/ ??' ??( ??) ??! ??< ??> ??-
???= ????= ?????/ ??????-
\??= \\??/ "??!" plain ?? and ?
TEXT;
return [$values, $text];
PHP;
    file_put_contents($directory . '/library/src/fixture.php', $source);
    library_trigraphs_run([PHP_BINARY, '-n', $directory . '/tools/build-library.php', 'dev']);
    $header = file_get_contents($directory . '/ext-src/php_swoole_library.h');
    Assert::true((bool) preg_match('/static const char\* swoole_library_source_fixture =\n(.*?);\n\n/s', $header, $matches));
    $cpp = "#include <cstdio>\n#include <cstring>\nstatic const char *source =\n" . $matches[1] . ";\n"
        . 'int main() { return std::fwrite(source, 1, std::strlen(source), stdout) == std::strlen(source) ? 0 : 1; }';
    file_put_contents($directory . '/fixture.cc', $cpp);
    library_trigraphs_run([
        'c++', '-std=c++14', '-trigraphs', '-Werror=trigraphs',
        $directory . '/fixture.cc', '-o', $directory . '/fixture',
    ]);
    $decoded = library_trigraphs_run([$directory . '/fixture']);
    Assert::same($decoded, rtrim(substr($source, strlen('<?php'))) . "\n");
    $result = eval($decoded);
    Assert::same($result[0], [
        'existing' => 'first', 'nested' => ['value' => 'nested'], 'null' => 'fallback',
    ]);
    echo "DONE\n";
} finally {
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($files as $file) {
        if ($file->isDir() && !$file->isLink()) {
            rmdir($file->getPathname());
        } else {
            unlink($file->getPathname());
        }
    }
    rmdir($directory);
}
?>
--EXPECT--
DONE
