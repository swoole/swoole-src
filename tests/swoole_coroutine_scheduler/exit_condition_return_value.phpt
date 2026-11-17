--TEST--
swoole_coroutine_scheduler: release refcounted exit_condition return values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class ExitConditionResult
{
    public static int $created = 0;
    public static int $destroyed = 0;

    public function __construct()
    {
        self::$created++;
    }

    public function __destruct()
    {
        self::$destroyed++;
    }
}

foreach ([false, true] as $wrapInArray) {
    Swoole\Coroutine::set([
        'exit_condition' => static function () use ($wrapInArray) {
            $result = new ExitConditionResult;
            return $wrapInArray ? ['result' => $result] : $result;
        },
    ]);
    Swoole\Timer::after(1, static function () {});
    Swoole\Event::wait();
    Assert::greaterThan(ExitConditionResult::$created, 0);
    Assert::same(ExitConditionResult::$destroyed, ExitConditionResult::$created);
}
echo "DONE\n";
?>
--EXPECT--
DONE
