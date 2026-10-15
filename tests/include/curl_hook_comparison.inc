<?php

function run_curl_hook_comparison(callable $test): void
{
    $modes = [SWOOLE_HOOK_CURL];
    ob_start();
    phpinfo(INFO_MODULES);
    $info = ob_get_clean();
    if (str_contains($info, 'curl-native => enabled')) {
        $modes[] = SWOOLE_HOOK_NATIVE_CURL;
    }
    foreach ($modes as $mode) {
        Swoole\Runtime::enableCoroutine($mode);
        Swoole\Coroutine\run(function () use ($test, $mode) {
            $probe = curl_init();
            if (($probe instanceof Swoole\Curl\Handler) !== ($mode === SWOOLE_HOOK_CURL)) {
                throw new RuntimeException('The requested curl implementation was not enabled');
            }
            curl_close($probe);
            $test($mode);
        });
    }
}
