--TEST--
Swoole\SendFile: typed descriptor properties and file ownership
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\SendFile;

$path = tempnam(sys_get_temp_dir(), 'swoole-sendfile-descriptor-');
$file = new SendFile($path);
Assert::same($file->filename, $path);
Assert::same($file->offset, 0);
Assert::same($file->length, 0);
Assert::false($file->deleteAfterSend);

foreach ([
    [fn () => new SendFile(''), ValueError::class],
    [fn () => new SendFile("a\0b"), ValueError::class],
    [fn () => $file->__construct($path), Error::class],
    [fn () => $file->filename = 'other', Error::class],
    [fn () => $file->offset = [], TypeError::class],
    [fn () => clone $file, Error::class],
    [fn () => serialize($file), Exception::class],
] as [$call, $class]) {
    try {
        $call();
        Assert::true(false, 'Expected an exception');
    } catch (Throwable $e) {
        Assert::isInstanceOf($e, $class);
    }
}

$file->deleteAfterSend = true;
unset($file);
Assert::true(is_file($path));
unlink($path);

$method = new ReflectionMethod(Swoole\Http\Response::class, 'sendfile');
Assert::same($method->getNumberOfParameters(), 4);
Assert::contains((string) $method->getParameters()[0]->getType(), SendFile::class);
Assert::same($method->getParameters()[3]->getName(), 'delete_file');
Assert::same((string) $method->getParameters()[3]->getType(), 'bool');
Assert::false($method->getParameters()[3]->getDefaultValue());
if (class_exists(Swoole\Server::class, false)) {
    $method = new ReflectionMethod(Swoole\Server::class, 'sendfile');
    Assert::same($method->getNumberOfParameters(), 5);
    Assert::contains((string) $method->getParameters()[1]->getType(), SendFile::class);
    Assert::same($method->getParameters()[4]->getName(), 'delete_file');
    Assert::same((string) $method->getParameters()[4]->getType(), 'bool');
    Assert::false($method->getParameters()[4]->getDefaultValue());
}
echo "DONE\n";
?>
--EXPECT--
DONE
