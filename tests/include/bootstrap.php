<?php
require_once __DIR__ . '/swoole.inc';

ini_set("assert.active", 1);
ini_set('swoole.display_errors', 'Off');
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_BAIL, 0);
assert_options(ASSERT_QUIET_EVAL, 0);

if (empty(getenv('SWOOLE_DEBUG'))) {
    if (method_exists('co', 'set')) {
        co::set([
            'log_level' => SWOOLE_LOG_INFO,
            'trace_flags' => 0,
        ]);
    }
}
