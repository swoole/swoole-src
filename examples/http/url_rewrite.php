<?php
/**
 * URL重写功能测试
 */

$http = new Swoole\Http\Server("0.0.0.0", 9501, SWOOLE_BASE);

$http->set([
    'enable_static_handler' => true,
    'document_root' => realpath(__DIR__.'/../www/'),
    'http_autoindex' => true,
    // URL重写规则配置
    'url_rewrite_rules' => [
        // 普通路径重写: 将 /api 开头的请求重写到 /static/api 目录
        '/api' => '/static/api',
        
        // 正则表达式重写: 将 /user/123 格式的请求重写到 /static/user.html?id=123
        '~^/user/(\\d+)$~' => '/static/user.html?id=$1',
        
        // 正则表达式重写: 将 /article/title-slug 格式的请求重写到 /static/article.html?slug=title-slug
        '~^/article/([\\w\\-]+)$~' => '/static/article.html?slug=$1'
    ]
]);

$http->on('request', function ($request, $response) {
    $response->header('Content-Type', 'text/plain; charset=utf-8');
    $response->end("动态处理: " . $request->server['request_uri']);
});

$http->on('start', function ($server) {
    echo "HTTP服务器已启动，监听 0.0.0.0:9501\n";
    echo "URL重写功能已启用\n";
    echo "测试示例:\n";
    echo "1. 普通重写: http://localhost:9501/api/test.txt -> /static/api/test.txt\n";
    echo "2. 正则重写: http://localhost:9501/user/123 -> /static/user.html?id=123\n";
    echo "3. 正则重写: http://localhost:9501/article/test-title -> /static/article.html?slug=test-title\n";
});

$http->start();