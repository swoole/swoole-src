--TEST--
swoole_thread: getResult transfers function, static method and script return values
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole_thread_result_');
$files = [$file];
try {
    $contents = str_repeat("thread\0result", 1024);
    file_put_contents($file, $contents);
    $thread = new Swoole\Thread('file_get_contents', $file);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same($thread->getResult(), $contents);
    Assert::same($thread->getResult(), $contents);

    foreach (["return 'script';" => 'script', 'return false;' => false, 'return null;' => null, '' => 1] as $body => $expected) {
        // Threads share OPcache; each entry script needs its own path rather than a rewritten cached file.
        $script = tempnam(sys_get_temp_dir(), 'swoole_thread_result_');
        $files[] = $script;
        file_put_contents($script, '<?php ' . $body);
        $thread = new Swoole\Thread($script);
        Assert::true($thread->join());
        Assert::same($thread->getExitStatus(), 0);
        Assert::same($thread->getResult(), $expected);
    }
    $thread = new Swoole\Thread('array_reverse', [1, 2, 3]);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same($thread->getResult(), [3, 2, 1]);

    $input = ['nested' => ['values' => [false, null, 3]], 'object' => (object) ['value' => 'kept']];
    $thread = new Swoole\Thread('array_values', $input);
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    $result = $thread->getResult();
    Assert::same($result[0], $input['nested']);
    Assert::same($result[1]->value, 'kept');
    $result[0]['values'][0] = true;
    Assert::same($thread->getResult()[0]['values'][0], false);
    Assert::same($input['nested']['values'][0], false);

    $thread = new Swoole\Thread('DateTimeImmutable::createFromFormat', '!Y-m-d', '2026-11-23');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
    Assert::same($thread->getResult()->format('Y-m-d'), '2026-11-23');
} finally {
    foreach ($files as $path) {
        unlink($path);
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
