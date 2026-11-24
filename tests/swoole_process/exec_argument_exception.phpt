--TEST--
swoole_process: exec stops on argument conversion failures and preserves later successful exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class InvalidExecArgument
{
    public function __toString(): string
    {
        throw new RuntimeException('argument conversion failed');
    }
}
class ValidExecArgument
{
    public function __toString(): string
    {
        return 'EXEC_OK';
    }
}

$process = new Swoole\Process(static function ($process) {
    try {
        $process->exec(PHP_BINARY, ['-n', '-r', 'echo "UNEXPECTED";', str_repeat('x', 4096), new InvalidExecArgument]);
        Assert::true(false, 'exec must propagate the conversion exception');
    } catch (RuntimeException $exception) {
        Assert::same($exception->getMessage(), 'argument conversion failed');
        echo "CAUGHT\n";
    }
    foreach ([
        [PHP_BINARY . "\0ignored", []],
        [PHP_BINARY, ['-n', '-r', 'echo "UNEXPECTED";', "bad\0argument"]],
    ] as [$file, $arguments]) {
        try {
            $process->exec($file, $arguments);
            Assert::true(false, 'exec must reject null bytes');
        } catch (ValueError $exception) {
            echo "INVALID\n";
        }
    }
    Assert::false(@$process->exec('/swoole-exec-nonexistent-' . getmypid(), [new ValidExecArgument]));
    Assert::true($process->exec(PHP_BINARY, ['-n', '-r', 'echo $argv[1], "\n";', new ValidExecArgument]));
}, true);
$process->start();
while (($output = $process->read()) !== '' && $output !== false) {
    echo $output;
}
Swoole\Process::wait(true);
?>
--EXPECT--
CAUGHT
INVALID
INVALID
EXEC_OK
