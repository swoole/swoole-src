#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';

if (PHP_VERSION_ID < 80000) {
    swoole_error('Require PHP version 8.0 or later, current version: '. PHP_VERSION);
    exit;
}

$builder = new SwooleLibraryBuilder();
$builder->libraryDir = LIBRARY_DIR;
$builder->librarySrcDir = LIBRARY_SRC_DIR;
$builder->checkFileChange = !isset($argv[1]) or $argv[1] != 'dev';
$builder->outputFile = ROOT_DIR . '/ext-src/php_swoole_library.h';
$builder->stripComments = true;
$builder->symbolPrefix = 'swoole';
$builder->srcPath = '@swoole-src/library';

/* Notice: Sort by dependency */
$builder->files = [
    # <basic> #
    'constants.php',
    # <std> #
    'std/exec.php',
    # <core> #
    'core/Constant.php',
    'core/StringObject.php',
    'core/MultibyteStringObject.php',
    'core/Exception/ArrayKeyNotExists.php',
    'core/ArrayObject.php',
    'core/ObjectProxy.php',
    'core/Coroutine/WaitGroup.php',
    'core/Coroutine/Server.php',
    'core/Coroutine/Server/Connection.php',
    'core/Coroutine/Barrier.php',
    'core/Coroutine/Http/ClientProxy.php',
    'core/Coroutine/Http/functions.php',
    # <core for connection pool> #
    'core/ConnectionPool.php',
    'core/Database/ObjectProxy.php',
    'core/Database/MysqliConfig.php',
    'core/Database/MysqliException.php',
    'core/Database/MysqliPool.php',
    'core/Database/MysqliProxy.php',
    'core/Database/MysqliStatementProxy.php',
    'core/Database/PDOConfig.php',
    'core/Database/PDOPool.php',
    'core/Database/PDOProxy.php',
    'core/Database/PDOStatementProxy.php',
    'core/Database/RedisConfig.php',
    'core/Database/RedisPool.php',
    # <core for HTTP> #
    'core/Http/Status.php',
    # <core for cURL> #
    'core/Curl/Exception.php',
    'core/Curl/Handler.php',
    # <core for FastCGI> #
    'core/FastCGI.php',
    'core/FastCGI/Record.php',
    'core/FastCGI/Record/Params.php',
    'core/FastCGI/Record/AbortRequest.php',
    'core/FastCGI/Record/BeginRequest.php',
    'core/FastCGI/Record/Data.php',
    'core/FastCGI/Record/EndRequest.php',
    'core/FastCGI/Record/GetValues.php',
    'core/FastCGI/Record/GetValuesResult.php',
    'core/FastCGI/Record/Stdin.php',
    'core/FastCGI/Record/Stdout.php',
    'core/FastCGI/Record/Stderr.php',
    'core/FastCGI/Record/UnknownType.php',
    'core/FastCGI/FrameParser.php',
    'core/FastCGI/Message.php',
    'core/FastCGI/Request.php',
    'core/FastCGI/Response.php',
    'core/FastCGI/HttpRequest.php',
    'core/FastCGI/HttpResponse.php',
    'core/Coroutine/FastCGI/Client.php',
    'core/Coroutine/FastCGI/Client/Exception.php',
    'core/Coroutine/FastCGI/Proxy.php',
    # <core for Process> #
    'core/Process/Manager.php',
    # <core for Server> #
    'core/Server/Admin.php',
    'core/Server/Helper.php',
    # <core for NameResolver> #
    'core/NameResolver.php',
    'core/NameResolver/Exception.php',
    'core/NameResolver/Cluster.php',
    'core/NameResolver/Redis.php',
    'core/NameResolver/Nacos.php',
    'core/NameResolver/Consul.php',
    # <core for functions> #
    'core/Coroutine/functions.php',
    # <ext> #
    'ext/curl.php',
    'ext/sockets.php',
    # <finalizer> #
    'functions.php',
    'alias.php',
    'alias_ns.php',
];

$builder->make();
