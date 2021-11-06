#!/usr/bin/env php
<?php

class Version
{
    public $major;
    public $minor;
    public $release;
    public $extra;
    public $api;

    const REGX_MAJOR = '#define\s+SWOOLE_MAJOR_VERSION\s+(\d+)#';
    const REGX_MINOR = '#define\s+SWOOLE_MINOR_VERSION\s+(\d+)#';
    const REGX_RELEASE = '#define\s+SWOOLE_RELEASE_VERSION\s+(\d+)#';
    const REGX_EXTRA = '#define\s+SWOOLE_EXTRA_VERSION\s+"(\w*)"#';
    const REGX_API = '#define\s+SWOOLE_API_VERSION_ID\s+(0x[0-9a-f]*)#';

    function getVersion()
    {
        $version = implode('.', [$this->major, $this->minor, $this->release]);
        if ($this->extra) {
            $version .= '-' . $this->extra;
        }
        return $version;
    }

    function getVersionId()
    {
        return intval(sprintf('%d%02d%02d', $this->major, $this->minor, $this->release));
    }

    function match($versionInfo) {
        preg_match(Version::REGX_MAJOR, $versionInfo, $match_major) or die('no match MAJOR_VERSION');
        preg_match(Version::REGX_MINOR, $versionInfo, $match_minor) or die('no match MAJOR_MINOR');;
        preg_match(Version::REGX_RELEASE, $versionInfo,
            $match_release) or die('no match RELEASE_VERSION');;
        preg_match(Version::REGX_EXTRA, $versionInfo, $match_extra) or die('no match EXTRA_VERSION');
        preg_match(Version::REGX_API, $versionInfo, $match_api) or die('no match API_VERSION_ID');

        $this->major = intval($match_major[1]);
        $this->minor = intval($match_minor[1]);
        $this->release = intval($match_release[1]);
        $this->extra = trim($match_extra[1]);
        $this->api = trim($match_api[1]);
    }
}

$type = empty($argv[1]) ? 'release' : trim($argv[1]);
$kernel_version_file = dirname(__DIR__) . '/include/swoole_version.h';
$cmake_file = dirname(__DIR__) . '/CMakeLists.txt';
$package_file = dirname(__DIR__) . '/package.xml';

$current = new Version;
$current->match(file_get_contents($kernel_version_file));

$next = clone $current;

if ($type == 'release') {
    if ($current->extra == '') {
        $next->release++;
        $next->extra = 'dev';
    } else {
        $next->extra = '';
    }
} elseif ($type == 'minor') {
    $next->minor++;
    $next->release = 0;
    $next->extra = 'dev';
} elseif ($type == 'major') {
    $next->major++;
    $next->minor = 0;
    $next->release = 0;
    $next->extra = 'dev';
} elseif ($type == 'api') {
    $date = substr($current->api, 2, strlen($current->api) - 3);
    if ($date == date('Ym')) {
        $c = substr($current->api, -1, 1);
        if ($c == 'f') {
            throw new RuntimeException("maximum exceeded[$current->api]");
        }
        $next->api = '0x' . $date . chr(ord($c) + 1);
    } else {
        $next->api = '0x' . date('Ym') . 'a';
    }
} else {
    exit("wrong version type");
}

if (empty($next->extra)) {
    $doc = file_get_contents($package_file);
    file_put_contents($package_file, str_replace($current->getVersion(), $next->getVersion(), $doc));
}

ob_start();
include __DIR__ . '/templates/version.tpl.h';
file_put_contents($kernel_version_file, ob_get_clean());

file_put_contents($cmake_file,
    preg_replace('#set\(SWOOLE_VERSION\s+[0-9\.\-a-z]+\)#i', 'set(SWOOLE_VERSION ' . $next->getVersion() . ')',
        file_get_contents($cmake_file)));
