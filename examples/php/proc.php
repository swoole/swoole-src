<?php
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

go(function () {
    $descriptorspec = array(
        0 => array("pipe", "r"),  // 标准输入，子进程从此管道中读取数据
        1 => array("pipe", "w"),  // 标准输出，子进程向此管道中写入数据
        2 => array("file", __DIR__ . "/error-output.txt", "a") // 标准错误，写入到一个文件
    );

    $cwd = '/tmp';
    $env = array('some_option' => 'aeiou');
    $process = proc_open('php', $descriptorspec, $pipes, $cwd, $env);

//    var_dump($process, $pipes);exit;

// $pipes 现在看起来是这样的：
// 0 => 可以向子进程标准输入写入的句柄
// 1 => 可以从子进程标准输出读取的句柄
// 错误输出将被追加到文件 /tmp/error-output.txt

    fwrite($pipes[0], '<?php sleep(1);print_r($_ENV); ?>');
    fclose($pipes[0]);

//    echo stream_get_contents($pipes[1]);
//    fclose($pipes[1]);

// 切记：在调用 proc_close 之前关闭所有的管道以避免死锁。
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
});
