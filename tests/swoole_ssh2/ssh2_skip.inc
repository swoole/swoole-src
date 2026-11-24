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

function ssh2t_needs_native_audit(): void
{
    skip_if_not_linux();
    skip('64-bit GNU loader auditing is required', PHP_INT_SIZE !== 8);
    skip('GNU libc is required for LD_AUDIT',
        !str_starts_with(trim((string) shell_exec('getconf GNU_LIBC_VERSION 2>/dev/null')), 'glibc '));
    skip_if_command_not_found('cc');
    skip_if_function_not_exist('exec');
    skip_if_function_not_exist('proc_open');
}

function ssh2t_needs_pubkey()
{
    skip('TEST_SSH2_USER not set', !TEST_SSH2_USER);
    skip_if_file_not_exist(TEST_SSH2_PUB_KEY);
    skip_if_file_not_exist(TEST_SSH2_PRIV_KEY);
}

function ssh2t_writes_remote()
{
    if (!TEST_SSH2_TEMPDIR) {
        skip('TEST_SSH2_TEMPDIR is empty');
    }
}

function ssh2t_needs_truncated_scp()
{
    skip('Truncated SCP fixture is not configured',
        !TEST_SSH2_TRUNCATED_SCP_USER || !TEST_SSH2_TRUNCATED_SCP_PASS);
}
