<?php
/**
 * This file is part of Swoole.
 *
 * @link     https://www.swoole.com
 * @contact  team@swoole.com
 * @license  https://github.com/swoole/library/blob/master/LICENSE
 */

declare(strict_types=1);
require_once 'ssh2_test.inc';

if (!defined('SSH2_POLLIN')) {
    echo 'skip extension not loaded';
}
if (TEST_SSH2_HOSTNAME === false) {
    echo 'skip TEST_SSH2_HOSTNAME not set';
}

function ssh2t_needs_auth()
{
    if (TEST_SSH2_AUTH == 'none') {
        echo "skip TEST_SSH2_AUTH == 'none'";
    }
}

function ssh2t_writes_remote()
{
    if (!TEST_SSH2_TEMPDIR) {
        echo 'skip TEST_SSH2_TEMPDIR is empty';
    }
}
