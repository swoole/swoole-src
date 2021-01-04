#!/usr/bin/env php
<?php
# @remicollet
# https://github.com/swoole/swoole-src/commit/ffff7ce074accf7b47768fca6eb238627d7a6b93#r30410846
# role="src" => not installed, so files only used for the build
# role="doc" => in $(pecl config-get doc_dir), which is /usr/share/doc/pecl/swoole on RPM distro (LICENSE being an exception, manually moved to /usr/share/licenses)
# role="test" => in $(pecl config-get test_dir), which is /usr/share/tests/pecl/swoole on RPM distro

require __DIR__ . '/bootstrap.php';

function check_source_ver(string $expect_ver, $source_file)
{
    static $source_ver_regex = '/(SWOOLE_VERSION +)("?)(?<ver>[\w\-.]+)("?)/';
    $replaced = false;
    _check:
    $source_content = file_get_contents($source_file);
    if (!preg_match($source_ver_regex, $source_content, $matches)) {
        swoole_log(
            "Warning: Match SWOOLE_VERSION Failed, skip check!\n",
            SWOOLE_COLOR_MAGENTA
        );
        return;
    }

    $source_ver = $matches['ver'];

    // auto fixed sub version values
    if (strpos($source_content, 'SWOOLE_MAJOR_VERSION') !== false) {
        $version_parts = array_values(array_filter(preg_split('/(?:\b)|(?:(?<=[0-9])(?=[a-zA-Z]))/',
            $source_ver), function (string $char) {
            return preg_match('/[0-9a-zA-Z]/', $char);
        }));
        list($major, $minor, $release, $extra) = $version_parts;
        $source_content = preg_replace(
            '/^(\#define[ ]+SWOOLE_VERSION_ID[ ]+)\d+$/m',
            '${1}' . sprintf('%d%02d%02d', $major, $minor, $release),
            $source_content
        );
        (function (&$source_content, $replacements) {
            foreach ($replacements as $replacement) {
                $regex = '/^(\#define[ ]+SWOOLE_' . $replacement[0] . '_VERSION[ ]+' . (is_numeric($replacement[1]) ? ')\d+()$' : '")[^"]*("$)') . '/m';
                $source_content = preg_replace(
                    $regex, '${1}' . $replacement[1] . '${2}',
                    $source_content,
                    1
                );
            }
        })($source_content, [['MAJOR', $major], ['MINOR', $minor], ['RELEASE', $release], ['EXTRA', $extra]]);
        file_put_contents($source_file, $source_content);
    }

    if (!preg_match('/^\d+?\.\d+?\.\d+?$/', $source_ver)) {
        $is_release_ver = false;
        swoole_warn("SWOOLE_VERSION v{$source_ver} is not a release version number in {$source_file}");
    } else {
        $is_release_ver = true;
    }
    $compare = version_compare($source_ver, $expect_ver);
    switch ($compare) {
        case -1: // <
            {
                if ($replaced) {
                    _replaced_error:
                    swoole_error("Fix version number failed in {$source_file}");
                }
                swoole_warn("SWOOLE_VERSION v{$source_ver} will be replaced to v{$expect_ver} in {$source_file}");
                $source_content = preg_replace(
                    $source_ver_regex, '$1${2}' . $expect_ver . '$4',
                    $source_content, 1, $replaced
                );
                if (!$replaced) {
                    goto _replaced_error;
                }
                file_put_contents($source_file, $source_content);
                $replaced = true;
                goto _check;
            }
            break;
        case 1: // >
            {
                if ($is_release_ver) {
                    swoole_error("Wrong SWOOLE_VERSION {$source_ver} in {$source_file}, please check your package.xml");
                }
            }
            break;
    }
}

// all check
swoole_execute_and_check(['php', __DIR__ . '/config-generator.php']);
swoole_execute_and_check(['php', __DIR__ . '/arginfo-check.php']);
swoole_execute_and_check(['php', __DIR__ . '/code-generator.php']);
if (file_exists(LIBRARY_DIR)) {
    swoole_execute_and_check(['php', __DIR__ . '/constant-generator.php']);
    swoole_execute_and_check(['php', __DIR__ . '/build-library.php']);
} else {
    swoole_warn('Unable to find source of library, this step will be skipped');
}
swoole_execute_and_check(['php', __DIR__ . '/phpt-fixer.php']);

// prepare
swoole_ok('Start to package...');
$this_dir = __DIR__;
$tests_dir = ROOT_DIR . '/tests/';
`cd {$tests_dir} && ./clean && cd {$this_dir}`;

$root_dir = SWOOLE_SOURCE_ROOT;

// check version definitions
$package_ver_regex = '/<version>\s+<release>(?<release_v>\d+?\.\d+?\.\d+?(?:-?(?:alpine|beta|rc\d*?))?)<\/release>\s+<api>(?<api_v>\d+?\.\d+?)<\/api>\s+<\/version>\s+<stability>\s+<release>(?<release_s>[a-z]+?)<\/release>\s+<api>(?<api_s>[a-z]+?)<\/api>\s+<\/stability>/i';
preg_match($package_ver_regex, file_get_contents(__DIR__ . '/../package.xml'), $matches);
$package_release_ver = $matches['release_v'];
$package_api_ver = $matches['api_v'];
$package_release_stable = $matches['release_s'];
$package_api_stable = $matches['api_s'];
$major_version = explode(".", $package_release_ver)[0];
if ((int) $major_version != $package_api_ver) {
    swoole_error("Wrong api version [{$package_api_ver}] with release version [{$package_release_ver}]");
}
if ($package_release_stable . $package_api_stable !== 'stable' . 'stable') {
    if (preg_match('/RC\d+$/', $package_release_ver)) {
        swoole_warn("It's not a stable version (RC)");
    } else {
        swoole_warn("It's not a stable version, can't be released by pecl");
    }
}
echo "[Version] => {$package_release_ver}\n";
echo "[API-Ver] => {$package_api_ver}\n";
echo "[RStable] => {$package_release_stable}\n";
echo "[AStable] => {$package_api_stable}\n";
check_source_ver($package_release_ver, dirname(__DIR__) . '/include/swoole_version.h');
check_source_ver($package_release_ver, dirname(__DIR__) . '/CMakeLists.txt');

// check file lists
$file_list_raw = swoole_git_files();
$file_list = [];
foreach ($file_list_raw as $file) {
    if (empty($file)) {
        continue;
    }
    if (is_dir("{$root_dir}/{$file}")) {
        continue;
    }
    if ($file === 'package.xml' || substr($file, 0, 1) === '.') {
        continue;
    }
    if (strpos($file, 'tests') === 0) {
        $role = 'test';
    } elseif (strpos($file, 'examples') === 0) {
        $role = 'doc';
    } else {
        $ext = pathinfo($file, PATHINFO_EXTENSION);
        $role = 'src';
        switch ($ext) {
            case 'phpt':
                $role = 'test';
                break;
            case 'md':
                $role = 'doc';
                break;
            case '':
                static $spacial_source_list = [
                    'Makefile' => true
                ];
                if ($spacial_source_list[pathinfo($file, PATHINFO_BASENAME)] ?? false) {
                    break;
                }
                if (substr(file_get_contents("{$root_dir}/{$file}"), 0, 2) !== '#!') {
                    $role = 'doc';
                }
                break;
        }
    }
    $file_list[] = "<file role=\"{$role}\" name=\"{$file}\" />\n";
}

// get content from package.xml and find out the file list
$content = file_get_contents(__DIR__ . '/../package.xml');
if (!preg_match('/([ ]*)\<dir[ ]name=\"\/\">/', $content, $matches)) {
    swoole_error('Match dir tag failed!');
}

// update file list
$space = strlen($matches[1]);
$space += 4;
$space = str_repeat(' ', $space);
$dir_tag = '<dir name="/">' . "\n";
$content = preg_replace('/(\<dir[ ]name=\"\/\">)([\s\S]*?)(\n[ ]*?\<\/dir>)/', '$1$3', $content, 1, $success);
if (!$success) {
    swoole_error('Replace old content failed!');
}
$content = str_replace($dir_tag, $dir_tag . $space . implode("{$space}", $file_list), $content, $success);
if (!$success) {
    swoole_error('Replace new content failed!');
}

// update date
date_default_timezone_set('Asia/Shanghai');
$date_tag = date('Y-m-d');
$content = preg_replace('/(<date\>)\d+?-\d+?-\d+?(<\/date>)/', '${1}' . $date_tag . '${2}', $content, $success);
if (!$success) {
    swoole_error('Replace date tag failed!');
}
$time_tag = date('H', time() + 3600) . ':00:00';
$content = preg_replace('/(<time\>)\d+?:\d+?:\d+?(<\/time>)/', '${1}' . $time_tag . '${2}', $content, $success);
if (!$success) {
    swoole_error('Replace time tag failed!');
}
if (!file_put_contents(__DIR__ . '/../package.xml', $content)) {
    swoole_error('Output package.xml failed!');
}

// pack
$package = trim(`cd {$root_dir} && pecl package`);
if (preg_match('/Warning/i', $package)) {
    $warn = explode("\n", $package);
    $package = array_pop($warn);
    $warn = implode("\n", $warn);
    swoole_log("{$warn}\n", SWOOLE_COLOR_MAGENTA);
}

// check package status
if (!preg_match('/Package (?<filename>swoole-.+?.tgz) done/', $package, $matches)) {
    swoole_error($package);
} else {
    $file_name = $matches['filename'];
    $file_path = "{$root_dir}/{$file_name}";
    $file_size = file_size($file_path);
    $file_hash = substr(md5_file($file_path), 0, 8);
    swoole_success("Package {$file_name} ({$file_size}) ({$file_hash}) done");
}
