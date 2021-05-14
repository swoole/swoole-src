#!/usr/bin/env php
<?php

class Version
{
    public $major;
    public $minor;
    public $release;
    public $extra;

    const REGX_MAJOR = '#define\s+SWOOLE_MAJOR_VERSION\s+(\d+)#';
    const REGX_MINOR = '#define\s+SWOOLE_MINOR_VERSION\s+(\d+)#';
    const REGX_RELEASE = '#define\s+SWOOLE_RELEASE_VERSION\s+(\d+)#';
    const REGX_EXTRA = '#define\s+SWOOLE_EXTRA_VERSION\s+"(\w*)"#';

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
}

$type = empty($argv[1]) ? 'release' : trim($argv[1]);
$kernel_version_file = dirname(__DIR__) . '/include/swoole_version.h';
$cmake_file = dirname(__DIR__) . '/CMakeLists.txt';
$package_file = dirname(__DIR__) . '/package.xml';

$versionInfo = file_get_contents($kernel_version_file);

preg_match(Version::REGX_MAJOR, $versionInfo, $match_major) or die('no match MAJOR_VERSION');
preg_match(Version::REGX_MINOR, $versionInfo, $match_minor) or die('no match MAJOR_MINOR');;
preg_match(Version::REGX_RELEASE, $versionInfo,
    $match_release) or die('no match RELEASE_VERSION');;
preg_match(Version::REGX_EXTRA, $versionInfo, $match_extra) or die('no match EXTRA_VERSION');

$current = new Version;
$current->major = intval($match_major[1]);
$current->minor = intval($match_minor[1]);
$current->release = intval($match_release[1]);
$current->extra = trim($match_extra[1]);

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
} else {
    exit("wrong version type");
}

if (empty($next->extra)) {
    $doc = new DOMDocument();
    $doc->load($package_file);
    $versions = $doc->getElementsByTagName("version");
    $versions[0]->getElementsByTagName('release')->item(0)->nodeValue = $next->getVersion();
    $versions[0]->getElementsByTagName('api')->item(0)->nodeValue = $next->major . '.0';
    $doc->save($package_file);
}

ob_start();
include __DIR__ . '/templates/version.tpl.h';
file_put_contents($kernel_version_file, ob_get_clean());

file_put_contents($cmake_file,
    preg_replace('#set\(SWOOLE_VERSION\s+[0-9\.\-a-z]+\)#i', 'set(SWOOLE_VERSION ' . $next->getVersion() . ')',
        file_get_contents($cmake_file)));
