<?php

// if no output, it means there is no mistake.

$root_dir = dirname(__DIR__);
$file_list_raw = explode("\n", `cd {$root_dir} && git ls-files`);
$file_list_raw = array_filter($file_list_raw, function (string $filename) {
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    return $ext === 'h' || $ext === 'c' || $ext === 'cc';
});
echo "\ncheck " . count($file_list_raw) . " source files...\n";
$all_count = 0;
array_walk($file_list_raw, function (string &$filename) use ($root_dir, &$all_count) {
    $filename = $root_dir . '/' . $filename;
    $content = file_get_contents($filename);
    preg_match_all(
        '/ZEND_BEGIN_ARG_INFO_EX\(.+, (\d+?)\)\n([\s\S]*?)ZEND_END_ARG_INFO\(\)/',
        $content, $arg_info_matches, PREG_SET_ORDER
    );
    array_walk($arg_info_matches, function (array $arg_info) use ($filename) {
        [$_, $arg_num, $arg_lines] = $arg_info;
        $total_num = substr_count($arg_lines, "ZEND_ARG_");
        if ((int)$arg_num > $total_num) {
            echo "\nin file {$filename}\n";
            var_dump($_);
        }
    });
    $count = substr_count($content, 'ZEND_PARSE_PARAMETERS_END');
    $all_count += $count;
    if ($count > 0) {
        $match_count = preg_match_all(
            '/\s*ZEND_PARSE_PARAMETERS_START(?:[_A-Z]*)\((?:[_A-Z]*, )?(?<min>[\d-]+), ?(?<max>[\d-]+)\)(?<params>[\s\S]+?)\s*ZEND_PARSE_PARAMETERS_END/',
            $content, $params_info_matches, PREG_SET_ORDER
        );
        // check num
        if (!assert(($count === $match_count) || preg_match('#/standard/exec\.c|zend_API\.h#', $filename) !== false)) {
            echo "\nin file {$filename}\n";
            var_dump($count, $match_count);
        }
        array_walk($params_info_matches, function (array $params_info) use ($filename) {
            ['min' => $declare_min, 'max' => $declare_max] = $params_info;
            $params = array_filter(preg_split('/[\s\\\\;]*\n[\s\\\\;]*/', $params_info['params']));
            $real_min = $real_max = $find_opt = 0;
            foreach ($params as $index => $param) {
                if (!preg_match('/[A-Z]+/', $param) || preg_match('/Z_PARAM_VARIADIC/', $param)) {
                    return;
                }
                if ($param === 'Z_PARAM_OPTIONAL') {
                    $find_opt = 1;
                } else {
                    if (!$find_opt) {
                        $real_min++;
                    }
                    $real_max++;
                }
            }
            if ($declare_min != $real_min || (!$declare_max == -1 && $declare_max != $real_max)) {
                echo "\nin file {$filename}\n({$declare_min} != {$real_min}), ({$declare_max} != {$real_max})\n";
                echo ltrim($params_info[0], "\n") . "\n";
            }
        });
    }
});
echo "\nall ZEND_PARSE_PARAMETERS_END is {$all_count}\n";
