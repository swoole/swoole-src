<?php

define("REDIS_SERVER_HOST", "127.0.0.1");
define("REDIS_SERVER_PORT", 6379);

$redis = new \swoole_redis();
$redis->on("close", function() { echo "close"; });

// !!!! For SUBSCRIBE
$redis->on("message", function() { var_dump(func_get_args()); });

$redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis, $connected) {
    if ($connected === false) {
        fputs(STDERR, "ERROR:$redis->errMsg($redis->errCode)\n");
        echo "connected fail";
        return;
    }
    echo "connected\n";

$luaScript = <<<LUA
error scripr
LUA;
$redis->eval($luaScript, 0, function(\swoole_redis $redis, $result) {
    if ($result === false) {
        // TODO WTF ? 错误信息呢？！
        // 这里的errMsg 与 errCode是socket的
        // 那redis原生的呢？！
        // 抓包可以看到错误返回信息
        fputs(STDERR, "ERROR:$redis->errMsg($redis->errCode)\n");
    } else {
        var_dump($result);
    }
    $redis->close();
});
    return;



    /**
     * evalsha
     * SCRIPT FLUSH ：清除所有脚本缓存
     * SCRIPT EXISTS ：根据给定的脚本校验和，检查指定的脚本是否存在于脚本缓存
     * SCRIPT LOAD ：将一个脚本装入脚本缓存，但并不立即运行它
     * SCRIPT KILL ：杀死当前正在运行的脚本
     */

    $luaScript = <<<LUA
return {KEYS[1],KEYS[2],ARGV[1],ARGV[2]}
LUA;
    $keyNum = 2;
    $key1 = "key1";
    $key2 = "key2";
    $val1 = "first";
    $val2 = "second";
    $r = $redis->eval($luaScript, $keyNum, $key1, $key2, $val1, $val2, function(\swoole_redis $redis, $result) {
        if ($result === false) {
            var_dump($redis);
            redis_error($redis);
            // WTF
            // -ERR Error compiling script (new swoole_function): user_script:1: unfinished string near '<eof>'
        } else {
            var_dump($result);
        }
        $redis->close();
    });
    assert($r === true);
});