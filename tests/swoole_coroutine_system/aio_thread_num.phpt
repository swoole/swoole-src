--TEST--
swoole_coroutine_system: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set([
    'aio_core_worker_num' => swoole_cpu_num(),
    'aio_max_wait_time' => 0.0005
]);

// init aio core workers
Co\run(function () {
    Co::readFile(__FILE__);
});

$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['dns_cache_capacity' => 0]);
$sch->add(function () {
    static $worker_num = 0;
    $n = 100;
    while ($n--) {
        $worker_num = max($worker_num, Co::stats()['aio_worker_num']);
        Swoole\Coroutine\System::sleep(0.001);
    }
    Assert::greaterThan($worker_num, swoole_cpu_num());
    phpt_var_dump($worker_num);
});
$sch->parallel(swoole_cpu_num() * [4, 16, 32, 64][PRESSURE_LEVEL], function () {
    Co::sleep(mt_rand(1, 5) / 1000);
    $result = Swoole\Coroutine\System::gethostbyname('www.baidu.com');
    Assert::notEmpty($result);
});
$sch->start();
?>
--EXPECT--
