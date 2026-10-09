--TEST--
swoole_runtime/file_hook: include and require preserve native stream operations
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$dir = __DIR__ . '/include_operations_tmp';
mkdir($dir);
file_put_contents($dir . '/return.php', '<?php return 42;');
file_put_contents($dir . '/nested.php', '<?php return require __DIR__ . "/return.php";');
Assert::same(include $dir . '/return.php', 42);
echo "outside: OK\n";

$autoload = function ($class) use ($dir) {
    require $dir . '/' . $class . '.php';
};
spl_autoload_register($autoload);

foreach (['file' => SWOOLE_HOOK_FILE, 'all' => SWOOLE_HOOK_ALL] as $name => $flags) {
    $class = 'SwooleIncludeHook_' . $name;
    $includeOnce = $dir . '/' . $name . '_include_once.php';
    $requireOnce = $dir . '/' . $name . '_require_once.php';
    file_put_contents($includeOnce, '<?php return 43;');
    file_put_contents($requireOnce, '<?php return 44;');
    file_put_contents($dir . '/' . $class . '.php', '<?php class ' . $class . ' {}');

    Swoole\Runtime::setHookFlags($flags);
    Swoole\Coroutine\run(function () use ($dir, $name, $flags, $class, $includeOnce, $requireOnce) {
        Assert::same(Swoole\Runtime::getHookFlags(), $flags);
        Assert::same(include $dir . '/return.php', 42);
        Assert::same(require $dir . '/return.php', 42);
        Assert::same(include_once $includeOnce, 43);
        Assert::same(include_once $includeOnce, true);
        Assert::same(require_once $requireOnce, 44);
        Assert::same(require_once $requireOnce, true);
        Assert::same(include $dir . '/nested.php', 42);
        Assert::same(get_class(new $class()), $class);

        $fp = fopen($dir . '/io.txt', 'w+');
        Assert::same(fwrite($fp, 'hello'), 5);
        Assert::same(fseek($fp, 0), 0);
        Assert::same(fread($fp, 5), 'hello');
        Assert::true(fclose($fp));
        echo "$name: OK\n";
    });
}

Swoole\Runtime::setHookFlags(0);
spl_autoload_unregister($autoload);
foreach (glob($dir . '/*') as $path) {
    unlink($path);
}
rmdir($dir);
echo "DONE\n";
?>
--CLEAN--
<?php
$dir = __DIR__ . '/include_operations_tmp';
if (is_dir($dir)) {
    foreach (glob($dir . '/*') as $path) {
        unlink($path);
    }
    rmdir($dir);
}
?>
--EXPECT--
outside: OK
file: OK
all: OK
DONE
