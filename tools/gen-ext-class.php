<?php

require __DIR__ . '/bootstrap.php';
if (empty($argv[1])) {
    exit("Usage: php {$argv[0]} module_name\n");
}

$module_name = trim($argv[1]);

$gen_class_name = function ($module_name) {
    $list = explode('_', $module_name);
    $class = '';
    foreach ($list as $li) {
        $class .= ucfirst($li);
    }
    return $class;
};

$replacement = [
    'file_name' => $module_name,
    'module_name' => $module_name,
    'var_name' => $module_name,
    'class_name' => $gen_class_name($module_name),
];

$replacement['type_name'] = $replacement['class_name'].'Object';
$replacement['php_var_name'] = "{$replacement['var_name']}_object";
$replacement['class_name'] = addcslashes($replacement['class_name'], '\\');
foreach ($replacement as $name => $value) {
    $replacement[strtoupper($name)] = strtoupper($value);
}

$result = '';
$srcTemplateFile = __DIR__ . '/templates/class.c';
$content = file_get_contents($srcTemplateFile);
foreach ($replacement as $name => $value) {
    $content = str_replace("{{{$name}}}", $value, $content);
}

file_put_contents(ROOT_DIR.'/ext-src/swoole_'.$module_name.'.cc', $content);

//, __DIR__ . '/templates/class.h'];

