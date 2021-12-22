[English](./README.md) | 中文

<h1>
<img width="200" height="120" align=center alt="Swoole Logo" src="swoole-logo.svg" />
</h1>

[![lib-swoole](https://github.com/swoole/swoole-src/workflows/lib-swoole/badge.svg)](https://github.com/swoole/swoole-src/actions?query=workflow%3Alib-swoole)
[![ext-swoole](https://github.com/swoole/swoole-src/workflows/ext-swoole/badge.svg)](https://github.com/swoole/swoole-src/actions?query=workflow%3Aext-swoole)
[![test-linux](https://github.com/swoole/swoole-src/workflows/test-linux/badge.svg)](https://github.com/swoole/swoole-src/actions?query=workflow%3Atest-linux)
[![Frameworks Tests](https://github.com/swoole/swoole-src/actions/workflows/framework.yml/badge.svg)](https://github.com/swoole/swoole-src/actions/workflows/framework.yml)
[![codecov](https://codecov.io/gh/swoole/swoole-src/branch/master/graph/badge.svg)](https://codecov.io/gh/swoole/swoole-src)

[![Twitter](https://badgen.net/badge/icon/twitter?icon=twitter&label)](https://twitter.com/phpswoole)
[![Discord](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.swoole.dev)
[![Latest Release](https://img.shields.io/github/release/swoole/swoole-src.svg)](https://github.com/swoole/swoole-src/releases/)
[![License](https://badgen.net/github/license/swoole/swoole-src)](https://github.com/swoole/swoole-src/blob/master/LICENSE)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/11654/badge.svg)](https://scan.coverity.com/projects/swoole-swoole-src)

**Swoole是一个C++编写的基于异步事件驱动和协程的并行网络通信引擎，为PHP提供高性能网络编程支持**

## ⚙️ 快速启动

可以直接使用 [Docker](https://github.com/swoole/docker-swoole) 来执行Swoole的代码，例如：

```bash
docker run --rm phpswoole/swoole "php --ri swoole"
```

具体的使用方式可以查看：[如何使用此镜像](https://github.com/swoole/docker-swoole#how-to-use-this-image) 。

或者可以在Swoole官网提供的 [在线编程](https://www.swoole.com/coding) 页面运行代码以及官网提供的示例代码。

## ✨ 事件驱动

Swoole中的网络请求处理是基于事件的，并且充分利用了底层的 epoll/kqueue 实现，使得为数百万个请求提供服务变得非常容易。

Swoole4使用全新的协程内核引擎，现在它拥有一个全职的开发团队，因此我们正在进入PHP历史上前所未有的时期，为性能的高速提升提供了独一无二的可能性。

## ⚡️ 协程

Swoole4或更高版本拥有高可用性的内置协程，您可以使用完全同步的代码来实现异步性能，PHP代码没有任何额外的关键字，底层会自动进行协程调度。

开发者可以将协程理解为超轻量级的线程, 你可以非常容易地在一个进程中创建成千上万个协程。

### MySQL客户端

并发1万个请求从MySQL读取海量数据仅需要0.2秒

```php
$s = microtime(true);
Co\run(function() {
    for ($c = 100; $c--;) {
        go(function () {
            $mysql = new Swoole\Coroutine\MySQL;
            $mysql->connect([
                'host' => '127.0.0.1',
                'user' => 'root',
                'password' => 'root',
                'database' => 'test'
            ]);
            $statement = $mysql->prepare('SELECT * FROM `user`');
            for ($n = 100; $n--;) {
                $result = $statement->execute();
                assert(count($result) > 0);
            }
        });
    }
});
echo 'use ' . (microtime(true) - $s) . ' s';
```

### 混合服务器

你可以在一个事件循环上创建多个服务：TCP，HTTP，Websocket和HTTP2，并且能轻松承载上万请求。

```php
function tcp_pack(string $data): string
{
    return pack('N', strlen($data)) . $data;
}
function tcp_unpack(string $data): string
{
    return substr($data, 4, unpack('N', substr($data, 0, 4))[1]);
}
$tcp_options = [
    'open_length_check' => true,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 4
];
```

```php
$server = new Swoole\WebSocket\Server('127.0.0.1', 9501, SWOOLE_BASE);
$server->set(['open_http2_protocol' => true]);
// http && http2
$server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    $response->end('Hello ' . $request->rawcontent());
});
// websocket
$server->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {
    $server->push($frame->fd, 'Hello ' . $frame->data);
});
// tcp
$tcp_server = $server->listen('127.0.0.1', 9502, SWOOLE_TCP);
$tcp_server->set($tcp_options);
$tcp_server->on('receive', function (Swoole\Server $server, int $fd, int $reactor_id, string $data) {
    $server->send($fd, tcp_pack('Hello ' . tcp_unpack($data)));
});
$server->start();
```
### 多种客户端

不管是DNS查询抑或是发送请求和接收响应，都是协程调度的，不会产生任何阻塞。

```php
go(function () {
    // http
    $http_client = new Swoole\Coroutine\Http\Client('127.0.0.1', 9501);
    assert($http_client->post('/', 'Swoole Http'));
    var_dump($http_client->body);
    // websocket
    $http_client->upgrade('/');
    $http_client->push('Swoole Websocket');
    var_dump($http_client->recv()->data);
});
go(function () {
    // http2
    $http2_client = new Swoole\Coroutine\Http2\Client('localhost', 9501);
    $http2_client->connect();
    $http2_request = new Swoole\Http2\Request;
    $http2_request->method = 'POST';
    $http2_request->data = 'Swoole Http2';
    $http2_client->send($http2_request);
    $http2_response = $http2_client->recv();
    var_dump($http2_response->data);
});
go(function () use ($tcp_options) {
    // tcp
    $tcp_client = new Swoole\Coroutine\Client(SWOOLE_TCP);
    $tcp_client->set($tcp_options);
    $tcp_client->connect('127.0.0.1', 9502);
    $tcp_client->send(tcp_pack('Swoole Tcp'));
    var_dump(tcp_unpack($tcp_client->recv()));
});
```

### 通道

通道(Channel)是协程之间通信交换数据的唯一渠道, 而协程+通道的开发组合即为著名的CSP编程模型。

在Swoole开发中，Channel常用于连接池的实现和协程并发的调度。

#### 连接池最简示例

在以下示例中，我们并发了一千个redis请求，通常的情况下，这已经超过了Redis最大的连接数，将会抛出连接异常， 但基于Channel实现的连接池可以完美地调度请求，开发者就无需担心连接过载。

```php
class RedisPool
{
    /**@var \Swoole\Coroutine\Channel */
    protected $pool;

    /**
     * RedisPool constructor.
     * @param int $size max connections
     */
    public function __construct(int $size = 100)
    {
        $this->pool = new \Swoole\Coroutine\Channel($size);
        for ($i = 0; $i < $size; $i++) {
            $redis = new \Swoole\Coroutine\Redis();
            $res = $redis->connect('127.0.0.1', 6379);
            if ($res == false) {
                throw new \RuntimeException("failed to connect redis server.");
            } else {
                $this->put($redis);
            }
        }
    }

    public function get(): \Swoole\Coroutine\Redis
    {
        return $this->pool->pop();
    }

    public function put(\Swoole\Coroutine\Redis $redis)
    {
        $this->pool->push($redis);
    }

    public function close(): void
    {
        $this->pool->close();
        $this->pool = null;
    }
}

go(function () {
    $pool = new RedisPool();
    // max concurrency num is more than max connections
    // but it's no problem, channel will help you with scheduling
    for ($c = 0; $c < 1000; $c++) {
        go(function () use ($pool, $c) {
            for ($n = 0; $n < 100; $n++) {
                $redis = $pool->get();
                assert($redis->set("awesome-{$c}-{$n}", 'swoole'));
                assert($redis->get("awesome-{$c}-{$n}") === 'swoole');
                assert($redis->delete("awesome-{$c}-{$n}"));
                $pool->put($redis);
            }
        });
    }
});
```

#### 生产和消费

Swoole的部分客户端实现了defer机制来进行并发，但你依然可以用协程和通道的组合来灵活地实现它。

```php
go(function () {
    // User: I need you to bring me some information back.
    // Channel: OK! I will be responsible for scheduling.
    $channel = new Swoole\Coroutine\Channel;
    go(function () use ($channel) {
        // Coroutine A: Ok! I will show you the github addr info
        $addr_info = Co::getaddrinfo('github.com');
        $channel->push(['A', json_encode($addr_info, JSON_PRETTY_PRINT)]);
    });
    go(function () use ($channel) {
        // Coroutine B: Ok! I will show you what your code look like
        $mirror = Co::readFile(__FILE__);
        $channel->push(['B', $mirror]);
    });
    go(function () use ($channel) {
        // Coroutine C: Ok! I will show you the date
        $channel->push(['C', date(DATE_W3C)]);
    });
    for ($i = 3; $i--;) {
        list($id, $data) = $channel->pop();
        echo "From {$id}:\n {$data}\n";
    }
    // User: Amazing, I got every information at earliest time!
});
```

### 定时器

```php
$id = Swoole\Timer::tick(100, function () {
    echo "⚙️ Do something...\n";
});
Swoole\Timer::after(500, function () use ($id) {
    Swoole\Timer::clear($id);
    echo "⏰ Done\n";
});
Swoole\Timer::after(1000, function () use ($id) {
    if (!Swoole\Timer::exists($id)) {
        echo "✅ All right!\n";
    }
});
```

#### 使用协程方式

```php
go(function () {
    $i = 0;
    while (true) {
        Co::sleep(0.1);
        echo "📝 Do something...\n";
        if (++$i === 5) {
            echo "🛎 Done\n";
            break;
        }
    }
    echo "🎉 All right!\n";
});
```

### 命名空间

Swoole提供了多种类命名规则以满足不同开发者的爱好

1. 符合PSR规范的命名空间风格
2. 便于键入的下划线风格
3. 协程类短名风格

## 🔥 强大的运行时钩子

在最新版本的Swoole中，我们添加了一项新功能，使PHP原生的同步网络库一键化成为协程库。

只需在脚本顶部调用`Swoole\Runtime::enableCoroutine()`方法并使用`php-redis`，并发1万个请求从Redis读取数据仅需0.1秒！

```php
Swoole\Runtime::enableCoroutine();
$s = microtime(true);
Co\run(function() {
    for ($c = 100; $c--;) {
        go(function () {
            ($redis = new Redis)->connect('127.0.0.1', 6379);
            for ($n = 100; $n--;) {
                assert($redis->get('awesome') === 'swoole');
            }
        });
    }
});
echo 'use ' . (microtime(true) - $s) . ' s';
```

调用它之后，Swoole内核将替换ZendVM中的Stream函数指针，如果使用基于`php_stream`的扩展，则所有套接字操作都可以在运行时动态转换为协程调度的异步IO。

### 你可以在一秒钟里做多少事?

睡眠1万次，读取，写入，检查和删除文件1万次，使用PDO和MySQLi与数据库通信1万次，创建TCP服务器和多个客户端相互通信1万次，创建UDP服务器和多个客户端相互通信1万次......一切都在一个进程中完美完成！

```php
Swoole\Runtime::enableCoroutine();
$s = microtime(true);
Co\run(function() {
    // i just want to sleep...
    for ($c = 100; $c--;) {
        go(function () {
            for ($n = 100; $n--;) {
                usleep(1000);
            }
        });
    }

    // 10k file read and write
    for ($c = 100; $c--;) {
        go(function () use ($c) {
            $tmp_filename = "/tmp/test-{$c}.php";
            for ($n = 100; $n--;) {
                $self = file_get_contents(__FILE__);
                file_put_contents($tmp_filename, $self);
                assert(file_get_contents($tmp_filename) === $self);
            }
            unlink($tmp_filename);
        });
    }

    // 10k pdo and mysqli read
    for ($c = 50; $c--;) {
        go(function () {
            $pdo = new PDO('mysql:host=127.0.0.1;dbname=test;charset=utf8', 'root', 'root');
            $statement = $pdo->prepare('SELECT * FROM `user`');
            for ($n = 100; $n--;) {
                $statement->execute();
                assert(count($statement->fetchAll()) > 0);
            }
        });
    }
    for ($c = 50; $c--;) {
        go(function () {
            $mysqli = new Mysqli('127.0.0.1', 'root', 'root', 'test');
            $statement = $mysqli->prepare('SELECT `id` FROM `user`');
            for ($n = 100; $n--;) {
                $statement->bind_result($id);
                $statement->execute();
                $statement->fetch();
                assert($id > 0);
            }
        });
    }

    // php_stream tcp server & client with 12.8k requests in single process
    function tcp_pack(string $data): string
    {
        return pack('n', strlen($data)) . $data;
    }

    function tcp_length(string $head): int
    {
        return unpack('n', $head)[1];
    }

    go(function () {
        $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true, 'backlog' => 128]]);
        $socket = stream_socket_server(
            'tcp://0.0.0.0:9502',
            $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx
        );
        if (!$socket) {
            echo "$errstr ($errno)\n";
        } else {
            $i = 0;
            while ($conn = stream_socket_accept($socket, 1)) {
                stream_set_timeout($conn, 5);
                for ($n = 100; $n--;) {
                    $data = fread($conn, tcp_length(fread($conn, 2)));
                    assert($data === "Hello Swoole Server #{$n}!");
                    fwrite($conn, tcp_pack("Hello Swoole Client #{$n}!"));
                }
                if (++$i === 128) {
                    fclose($socket);
                    break;
                }
            }
        }
    });
    for ($c = 128; $c--;) {
        go(function () {
            $fp = stream_socket_client("tcp://127.0.0.1:9502", $errno, $errstr, 1);
            if (!$fp) {
                echo "$errstr ($errno)\n";
            } else {
                stream_set_timeout($fp, 5);
                for ($n = 100; $n--;) {
                    fwrite($fp, tcp_pack("Hello Swoole Server #{$n}!"));
                    $data = fread($fp, tcp_length(fread($fp, 2)));
                    assert($data === "Hello Swoole Client #{$n}!");
                }
                fclose($fp);
            }
        });
    }

    // udp server & client with 12.8k requests in single process
    go(function () {
        $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
        $socket->bind('127.0.0.1', 9503);
        $client_map = [];
        for ($c = 128; $c--;) {
            for ($n = 0; $n < 100; $n++) {
                $recv = $socket->recvfrom($peer);
                $client_uid = "{$peer['address']}:{$peer['port']}";
                $id = $client_map[$client_uid] = ($client_map[$client_uid] ?? -1) + 1;
                assert($recv === "Client: Hello #{$id}!");
                $socket->sendto($peer['address'], $peer['port'], "Server: Hello #{$id}!");
            }
        }
        $socket->close();
    });
    for ($c = 128; $c--;) {
        go(function () {
            $fp = stream_socket_client("udp://127.0.0.1:9503", $errno, $errstr, 1);
            if (!$fp) {
                echo "$errstr ($errno)\n";
            } else {
                for ($n = 0; $n < 100; $n++) {
                    fwrite($fp, "Client: Hello #{$n}!");
                    $recv = fread($fp, 1024);
                    list($address, $port) = explode(':', (stream_socket_get_name($fp, true)));
                    assert($address === '127.0.0.1' && (int)$port === 9503);
                    assert($recv === "Server: Hello #{$n}!");
                }
                fclose($fp);
            }
        });
    }
});
echo 'use ' . (microtime(true) - $s) . ' s';
```

## ⌛️ 安装

> 和任何开源项目一样, Swoole总是在**最新的发行版**提供最可靠的稳定性和最强的功能, 请尽量保证你使用的是最新版本

### 编译需求

+ Linux, OS X 系统 或 CygWin, WSL
+ PHP 7.2.0 或以上版本 (版本越高性能越好)
+ GCC 4.8 及以上

### 1. 使用PHP官方的PECL工具安装 (初学者)

```shell
pecl install swoole
```

### 2. 从源码编译安装 (推荐)

> 非内核开发研究之用途, 请下载[发布版本](https://github.com/swoole/swoole-src/releases)的源码编译

```shell
cd swoole-src && \
phpize && \
./configure && \
make && sudo make install
```

#### 启用扩展

编译安装到系统成功后, 需要在`php.ini`中加入一行`extension=swoole.so`来启用Swoole扩展

#### 额外编译参数

> 使用例子: `./configure --enable-openssl --enable-sockets`

+ `--enable-openssl` 或 `--with-openssl-dir=DIR`
+ `--enable-sockets`
+ `--enable-http2`
+ `--enable-mysqlnd` (需要 mysqlnd, 只是为了支持`mysql->escape`方法)
+ `--enable-swoole-json`
+ `--enable-swoole-curl`

### 升级

>  ⚠️ 如果你要从源码升级, 别忘记在源码目录执行 `make clean`

1. `pecl upgrade swoole`
2. `cd swoole-src && git pull && make clean && make && sudo make install`
3. 如果你改变了PHP版本, 请重新执行 `phpize clean && phpize`后重新编译

## 💎 框架 & 组件

+ [**Hyperf**](https://github.com/hyperf/hyperf) 是一个高性能、高灵活性的协程框架，存在丰富的可能性，如实现分布式中间件，微服务架构等
+ [**Swoft**](https://github.com/swoft-cloud) 是一个现代化的面向切面的高性能协程全栈组件化框架
+ [**Easyswoole**](https://www.easyswoole.com) 是一个极简的高性能的框架，让代码开发就好像写`echo "hello world"`一样简单
+ [**MixPHP**](https://github.com/mix-php/mix) 是一个功能强大的单线程协程框架，轻量、简单而优雅
+ [**imi**](https://github.com/Yurunsoft/imi) 是基于 PHP Swoole 的高性能协程应用开发框架，它支持 HttpApi、WebSocket、TCP、UDP 服务的开发。
+ [**Saber**](https://github.com/swlib/saber) 是一个人性化的高性能HTTP客户端组件，几乎拥有一切你可以想象的强大功能
+ [**One**](https://github.com/lizhichao/one) 是一个极简高性能php框架，支持[swoole | php-fpm ]环境

## 🛠 开发 & 讨论

+ __中文文档__: <https://wiki.swoole.com>
+ __Document__: <https://www.swoole.co.uk/docs>
+ __IDE Helper & API__: <https://github.com/swoole/ide-helper>
+ __调试工具__: <https://github.com/swoole/yasd>
+ __中文社区及QQ群__: <https://wiki.swoole.com/#/other/discussion>
+ __Twitter__: <https://twitter.com/php_swoole>
+ __Slack Group__: <https://swoole.slack.com>

## 🍭 性能测试

+ 在开源的 [Techempower Web Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r17) 压测平台上，Swoole使用MySQL数据库压测的成绩一度位居首位， 所有IO性能测试都位列第一梯队。
+ 你可以直接运行 [Benchmark Script](https://github.com/swoole/benchmark/blob/master/benchmark.php) 来快速地测试出Swoole提供的Http服务在你的机器上所能达到的最大QPS

## 🔰️ 安全问题

安全问题应通过电子邮件私下报告给Swoole开发团队[team@swoole.com](mailto:team@swoole.com)。您将会在24小时内收到回复，若由于某些原因您没有收到回复，请再次通过电子邮件跟进以确保我们收到了您的原始消息。

## 🖊️ 如何贡献

非常欢迎您对Swoole的开发作出贡献！

你可以选择以下方式向Swoole贡献：

+ [发布issue进行问题反馈和建议](https://github.com/swoole/swoole-src/issues)
+ 通过Pull Request提交修复
+ 完善我们的文档和例子

## ❤️ 贡献者

项目的发展离不开以下贡献者的努力! [[Contributor](https://github.com/swoole/swoole-src/graphs/contributors)].
<a href="https://github.com/swoole/swoole-src/graphs/contributors"><img src="https://opencollective.com/swoole-src/contributors.svg?width=890&button=false" /></a>

## 📃 开源协议

Apache License Version 2.0 see http://www.apache.org/licenses/LICENSE-2.0.html
