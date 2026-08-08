<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);
require_once __DIR__ . '/../include/skipif.inc';
require_once 'ssh2_test.inc';

skip('SSH2 support is not enabled', !function_exists('ssh2_exec'));
skip('TEST_SSH2_HOSTNAME not set', !TEST_SSH2_HOSTNAME);

function ssh2t_needs_auth()
{
    if (TEST_SSH2_AUTH == 'none') {
        skip("TEST_SSH2_AUTH == 'none'");
    }
}

function ssh2t_writes_remote()
{
    if (!TEST_SSH2_TEMPDIR) {
        skip('TEST_SSH2_TEMPDIR is empty');
    }
}
