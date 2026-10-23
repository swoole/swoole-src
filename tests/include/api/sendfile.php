<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);

function make_sendfile(string $path, int $offset = 0, int $length = 0): Swoole\SendFile
{
    $file                  = new Swoole\SendFile($path);
    $file->offset          = $offset;
    $file->length          = $length;
    $file->deleteAfterSend = true;
    return $file;
}
