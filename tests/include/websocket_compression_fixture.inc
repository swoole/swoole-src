<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);

// Fixed binary input that does not compress well, independent of the random seed.
$data = '';
for ($i = 0; $i < 2048; $i++) {
    $data .= hash('sha512', pack('N', $i), true);
}

$payloads = [];
foreach ([125, 126, 0, 1, 2, 3, 124, 127, 128, 1024, 4095, 4096,
    16383, 16384, 32767, 32768, 65534, 65535, 65536, 131071, 131072, 125, 1] as $length) {
    $payloads[] = substr($data, 0, $length);
}
$payloads[] = str_repeat('swoole-websocket-compression:', 4096);

return $payloads;
