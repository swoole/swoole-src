<?php
Co::set(['hook_flags'=> 0]);
// php -d swoole.blocking_detection=on -d swoole.blocking_threshold=500000 blocking.php
function  sleep_test()
{
    echo "Start\n";
    sleep(1);
    echo "End\n";
}

function redis_test()
{
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    $result = $redis->blPop('queue_name', 1.5);
    if ($result) {
        list($queueName, $value) = $result;
        echo "获取到数据: {$value}\n";
    }
}

function main()
{
    sleep_test();
    redis_test();
}

Co\run(function () {
    main();
});
