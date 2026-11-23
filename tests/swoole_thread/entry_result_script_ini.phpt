--TEST--
swoole_thread: script results preserve prepend, append and working-directory semantics
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_php_version_lower_than('8.4');
?>
--INI--
auto_prepend_file={PWD}/fixtures/entry-result-prepend.inc
auto_append_file={PWD}/fixtures/entry-result-append.inc
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$file = tempnam(sys_get_temp_dir(), 'swoole_thread_ini_');
file_put_contents($file, <<<'PHP'
<?php
return ['order' => $GLOBALS['thread_result_order'], 'cwd' => getcwd()];
PHP);
try {
    $cwd = getcwd();
    $thread = new Swoole\Thread($file);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    $result = $thread->getResult();
    Assert::same($result['order'], 'prepend');
    Assert::same($result['cwd'], dirname(realpath($file)));
    Assert::same(getcwd(), $cwd);
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
