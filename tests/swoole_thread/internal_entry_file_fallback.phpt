--TEST--
swoole_thread: user functions and non-static methods retain script entry semantics without autoload
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_nts();
?>
--INI--
display_errors=0
log_errors=0
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function swoole_thread_user_entry(): void
{
    throw new RuntimeException('User functions must not become direct thread entries');
}
class ThreadUserEntry
{
    public static function run(): void
    {
        throw new RuntimeException('User classes must not become direct thread entries');
    }
    public static function __callStatic(string $method, array $args): void
    {
        throw new RuntimeException('Magic methods must not become direct thread entries');
    }
}
$autoloads = 0;
spl_autoload_register(function (string $class) use (&$autoloads): void {
    ++$autoloads;
});
foreach (['swoole_thread_user_entry', 'ThreadUserEntry::run', 'ThreadUserEntry::missing', 'ThreadUnknownEntry::run', 'DateTimeImmutable::format'] as $entry) {
    $thread = new Swoole\Thread($entry);
    Assert::true($thread->join());
    Assert::assert($thread->getExitStatus() !== 0);
}
Assert::same($autoloads, 0);
$file = tempnam(sys_get_temp_dir(), 'swoole_thread_script_');
try {
    file_put_contents($file, '<?php var_dump(Swoole\\Thread::getArguments());');
    $thread = new Swoole\Thread($file, 'script');
    Assert::true($thread->join());
    Assert::same($thread->getExitStatus(), 0);
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
array(1) {
  [0]=>
  string(6) "script"
}
DONE
