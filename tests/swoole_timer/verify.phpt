--TEST--
swoole_timer: verify timer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $test_times = 30;
    // $err = 0;
    $max_residuals = -1;
    for ($i = $test_times; $i-- > 1;) {
        $seconds = 0.001 * $i;
        $start = microtime(true);
        co::sleep($seconds);
        $use = microtime(true) - $start;
        $residuals = round(max($seconds, $use) - min($seconds, $use), 3);
        if ($residuals > $max_residuals) {
            $max_residuals = $residuals;
        }
        assert($residuals <= 0.001);
        // if (!($residuals < 0.0011)) {
        //     $err++;
        // }
    }
    var_dump(round($max_residuals, 2));
    // $percent = $err / $test_times;
    // if (!assert($percent < (1 / $test_times))) {
    //     echo ($percent * 100) . '% error, max residuals is ' . $max_residuals . "\n";
    // }
});
?>
--EXPECT--
float(0)
