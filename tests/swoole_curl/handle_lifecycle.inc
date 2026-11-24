<?php

function check_lifecycle(bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException('Unexpected curl lifecycle result');
    }
}

function create_lifecycle_multi(bool $cycle = false): CurlMultiHandle
{
    $multi = curl_multi_init();
    $easy = curl_init();
    if ($cycle) {
        curl_setopt($easy, CURLOPT_WRITEFUNCTION, static function ($easy, $data) use ($multi) {
            return strlen($data);
        });
    }
    check_lifecycle(curl_multi_add_handle($multi, $easy) === CURLM_OK);
    return $multi;
}

function clone_lifecycle_easy(): void
{
    $easy = curl_init();
    curl_setopt($easy, CURLOPT_PRIVATE, 'original');
    $clone = clone $easy;
    $copy = curl_copy_handle($easy);
    check_lifecycle(curl_getinfo($clone, CURLINFO_PRIVATE) === 'original');
    check_lifecycle(curl_getinfo($copy, CURLINFO_PRIVATE) === 'original');
    curl_reset($easy);
    unset($easy);
    curl_setopt($clone, CURLOPT_PRIVATE, 'clone');
    check_lifecycle(curl_getinfo($clone, CURLINFO_PRIVATE) === 'clone');
    check_lifecycle(curl_getinfo($copy, CURLINFO_PRIVATE) === 'original');
}

$mode = $argv[1];
if ($mode === 'native-shutdown') {
    $multi = curl_multi_init();
    @curl_multi_close($multi);
} elseif ($mode === 'native-attached-shutdown') {
    $multi = create_lifecycle_multi();
} elseif ($mode === 'native-unset') {
    $multi = create_lifecycle_multi();
    unset($multi);
} elseif ($mode === 'native-gc') {
    $multi = create_lifecycle_multi(true);
    unset($multi);
    check_lifecycle(gc_collect_cycles() > 0);
} elseif ($mode === 'native-clone') {
    clone_lifecycle_easy();
    $easy = curl_init();
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    Swoole\Coroutine\run(static function () use ($easy) {
        // Cloning a native object inside a coroutine must still use ext-curl.
        $clone = clone $easy;
    });
    unset($easy);
} elseif ($mode === 'native-hook-enabled') {
    $multi = create_lifecycle_multi();
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    unset($multi);
} elseif ($mode === 'native-after-co') {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    Swoole\Coroutine\run(static function () {});
    $multi = create_lifecycle_multi();
    unset($multi);
} elseif ($mode === 'native-in-co') {
    Swoole\Coroutine\run(static function () {
        Swoole\Runtime::enableCoroutine(0);
        $multi = create_lifecycle_multi();
        unset($multi);
    });
} elseif ($mode === 'native-marker') {
    $multi = create_lifecycle_multi();
    // A public compatibility property cannot change which library owns the object.
    $multi->in_coroutine = true;
    unset($multi);
} elseif ($mode === 'co-add-native') {
    $easy = curl_init();
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    Swoole\Coroutine\run(static function () use ($easy) {
        $multi = curl_multi_init();
        check_lifecycle(@curl_multi_add_handle($multi, $easy) === CURLM_BAD_EASY_HANDLE);
    });
    unset($easy);
} else {
    Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_NATIVE_CURL);
    Swoole\Coroutine\run(static function () use ($mode, &$multi) {
        if ($mode === 'co-clone') {
            clone_lifecycle_easy();
        } else {
            $multi = create_lifecycle_multi($mode === 'co-gc');
            check_lifecycle($multi->in_coroutine === true);
        }
    });
    if ($mode === 'co-hook-disabled' || $mode === 'co-gc') {
        Swoole\Runtime::enableCoroutine(0);
    }
    if ($mode === 'co-marker') {
        $multi->in_coroutine = false;
    }
    unset($multi);
    if ($mode === 'co-gc') {
        check_lifecycle(gc_collect_cycles() > 0);
    }
}
echo "DONE\n";
