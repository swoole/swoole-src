<?php
// if no output, it means there is no mistake.
$list = array_filter(scandir(__DIR__.'/../'), function (string $name) {
    return substr($name, -2, 2) === '.c';
});
array_walk($list, function (string $filename) {
    $content = file_get_contents(__DIR__."/../{$filename}");
    preg_match_all(
        '/ZEND_BEGIN_ARG_INFO_EX\(.+, (\d+?)\)\n([\s\S]*?)ZEND_END_ARG_INFO\(\)/',
        $content, $arg_info_matches, PREG_SET_ORDER
    );
    array_walk($arg_info_matches, function (array $arg_info) {
        [$_, $arg_num, $arg_lines] = $arg_info;
        $total_num = substr_count($arg_lines, "ZEND_ARG_");
        if ((int)$arg_num > $total_num) {
            var_dump($_);
        }
    });
});