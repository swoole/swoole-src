#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

$swoole_c = ROOT_DIR . '/ext-src/php_swoole.cc';
$swoole_c_content = file_get_contents($swoole_c);

$error_h = ROOT_DIR . '/include/swoole_error.h';
$error_h_content = file_get_contents($error_h);

$log_h = ROOT_DIR . '/include/swoole_log.h';
$log_h_content = file_get_contents($log_h);

//---------------------------------------------------------------------------
//                     generate ERROR constants
//---------------------------------------------------------------------------
if (!preg_match_all('/SW_ERROR_[0-9A-Z_]+/', $error_h_content, $matches_error,
        PREG_PATTERN_ORDER) || empty($matches_error[0])) {
    swoole_error('Match ERROR enums error!');
}
$matches_error[0] = array_unique($matches_error[0]);
// trim start and end
array_shift($matches_error[0]);
array_pop($matches_error[0]);

// generate ERROR constants
$define_output = '';
foreach ($matches_error[0] as $match) {
    // convert error code to define
    $constant_name = str_replace('SW_', 'SWOOLE_', $match);
    $constant_value = $match;
    $define_output .= space(4) . "SW_REGISTER_LONG_CONSTANT(\"{$constant_name}\", {$constant_value});\n";
}
$swoole_c_content = preg_replace(
    '/ *?(?:SW_REGISTER_LONG_CONSTANT\("SWOOLE_ERROR_[0-9A-Z_]+?", SW_ERROR_[0-9A-Z_]+?\);\n *)+/',
    $define_output, $swoole_c_content, 1, $is_ok
);
swoole_check($is_ok, 'Generate ERROR constants');

//---------------------------------------------------------------------------
//                     generate TRACE constants
//---------------------------------------------------------------------------
if (!preg_match_all('/SW_TRACE_[0-9A-Z_]+/', $log_h_content, $matches_trace,
        PREG_PATTERN_ORDER) || empty($matches_trace[0])) {
    swoole_error('Match TRACE enums error!');
}
$matches_trace[0] = array_unique($matches_trace[0]);
$define_output = '';
foreach ($matches_trace[0] as $match) {
    // convert error code to define
    $constant_name = str_replace('SW_', 'SWOOLE_', $match);
    $constant_value = $match;
    $define_output .= space(4) . "SW_REGISTER_LONG_CONSTANT(\"{$constant_name}\", {$constant_value});\n";
}
$swoole_c_content = preg_replace(
    '/ *?(?:SW_REGISTER_LONG_CONSTANT\("SWOOLE_TRACE_[0-9A-Z_]+?", SW_TRACE_[0-9A-Z_]+?\);\n *)+/',
    $define_output, $swoole_c_content, 1, $is_ok
);
swoole_check($is_ok, 'Generate TRACE constants');

file_put_contents($swoole_c, $swoole_c_content);

// generate ERROR strings
$swoole_error_cc = ROOT_DIR . '/src/core/error.cc';
$swoole_error_cc_content = file_get_contents($swoole_error_cc);
$swstrerror_output = space(4) . "switch(code) {\n";
foreach ($matches_error[0] as $match) {
    // convert error code to swstrerror
    $sw_error_str = implode(' ', explode('_', strtolower(str_replace('SW_ERROR_', '', $match))));
    $replaces = [
        'co ' => 'Coroutine ',
        'php ' => 'PHP ',
        'ssl ' => 'SSL ',
        'dnslookup ' => 'DNS Lookup '
    ];
    $sw_error_str = str_replace(array_keys($replaces), array_values($replaces), $sw_error_str);
    $sw_error_str[0]= strtoupper($sw_error_str[0]);
    $swstrerror_output .= space(4) . "case {$match}:\n" . space(8) . "return \"{$sw_error_str}\";\n";
}
$swstrerror_output .= <<<CPP
    default:
        static char buffer[32];
#ifndef __MACH__
        snprintf(buffer, sizeof(buffer), "Unknown error %d", code);
#else
        snprintf(buffer, sizeof(buffer), "Unknown error: %d", code);
#endif
        return buffer;
    }
CPP;
$swstrerror_output .= "\n";
$swoole_error_cc_content = preg_replace(
    '/(\* swstrerror \{\{\{\*\/\n)([\s\S]+?)(\/\*\}\}\}\*\/)/',
    '${1}' . $swstrerror_output . space(4).'${3}',
    $swoole_error_cc_content, 1, $is_ok
);
swoole_check($is_ok, 'Generate ERROR stringify');
file_put_contents($swoole_error_cc, $swoole_error_cc_content);

swoole_success('Generate all source codes OK!');
