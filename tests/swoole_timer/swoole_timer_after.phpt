--TEST--
swoole_timer: swoole_timer_after,swoole_timer_exists,swoole_timer_clear
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
class TimerTest {
    public static $count = 0;
    private $timer_id = null;

    protected function resetTimer($ms) {
        if ($this->timer_id && swoole_timer_exists($this->timer_id)) {
            swoole_timer_clear($this->timer_id);
            $this->timer_id = null;
        }
        if (self::$count == 10) {
            return;
        }
        $this->timer_id = swoole_timer_after($ms, array($this, 'onTimerTick'));
        assert($this->timer_id > 0);
    }

    public function onTimerTick() {
        self::$count++;
        echo "onTimerTick:" . self::$count . "\n";
        $this->resetTimer(10);
    }
}

$timer_test = new TimerTest();
$timer_test->onTimerTick();

?>
--EXPECT--
onTimerTick:1
onTimerTick:2
onTimerTick:3
onTimerTick:4
onTimerTick:5
onTimerTick:6
onTimerTick:7
onTimerTick:8
onTimerTick:9
onTimerTick:10
