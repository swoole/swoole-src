English | [中文](./README-CN.md)

Swoole
======
[![Latest Version](https://img.shields.io/github/release/swoole/swoole-src.svg?style=flat-square)](https://github.com/swoole/swoole-src/releases)
[![Build Status](https://api.travis-ci.org/swoole/swoole-src.svg)](https://travis-ci.org/swoole/swoole-src)
[![License](https://img.shields.io/badge/license-apache2-blue.svg)](LICENSE)
[![Join the chat at https://gitter.im/swoole/swoole-src](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/swoole/swoole-src?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/11654/badge.svg)](https://scan.coverity.com/projects/swoole-swoole-src)
[![Backers on Open Collective](https://opencollective.com/swoole-src/backers/badge.svg)](#backers) 
[![Sponsors on Open Collective](https://opencollective.com/swoole-src/sponsors/badge.svg)](#sponsors) 

![](./mascot.png)

**Swoole is an event-driven asynchronous & coroutine-based concurrency networking communication engine with high performance written in C and C++ for PHP.**

## ✨Event-based

The network layer in Swoole is event-based and takes full advantage of the underlying epoll/kqueue implementation, making it really easy to serve millions of requests.

Swoole4 use a brand new engine kernel and now it has a full-time developer team, so we are entering an unprecedented period in PHP history which offers a unique possibility for a rapid evolution in performance.

## ⚡️Coroutine

Swoole4 or later supports the built-in coroutine with high availability, and you can use fully synchronized code to implement asynchronous performance. PHP code without any additional keywords, the underlying automatic coroutine-scheduling.

Developers can understand coroutines as ultra-lightweight threads, and you can easily create thousands of coroutines in a single process.

### MySQL

Concurrency 10k requests to read data from MySQL takes only 0.2s!

```php
$s = microtime(true);
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
Swoole\Event::wait();
echo 'use ' . (microtime(true) - $s) . ' s';
```

### Mixed Server

You can create multiple services on the single event loop: TCP, HTTP, Websocket and HTTP2, and easily handle thousands of requests.

```php
function tcp_pack(string $data): string
{
    return pack('n', strlen($data)) . $data;
}
function tcp_unpack(string $data): string
{
    return substr($data, 2, unpack('n', substr($data, 0, 2))[1]);
}
$tcp_options = [
    'open_length_check' => true,
    'package_length_type' => 'n',
    'package_length_offset' => 0,
    'package_body_offset' => 2
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

### Kinds of Clients

Whether you DNS query or send requests or receive responses, all of these are scheduled by coroutine automatically.

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
    $http2_request = new Swoole\Http2\Reuqest;
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

### Channel

Channel is the only way for exchanging data between coroutines, the development combination of the `Coroutine + Channel` is the famous CSP programming model.

In Swoole development, Channel is usually used for implementing connection pool or scheduling coroutine concurrent.

#### The simplest example of a connection pool

In the following example, we have a thousand concurrently requests to redis. Normally, this has exceeded the maximum number of Redis connections setting and will throw a connection exception, but the connection pool based on Channel can perfectly schedule requests. We don't have to worry about connection overload.

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
            $redis = new Swoole\Coroutine\Redis();
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

#### Production & Consumption

Some Swoole's clients implement the defer mode for concurrency, but you can still implement it flexible with a combination of coroutines and channels.

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

### Timer

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
#### Use coroutine way

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

## 🔥 Amazing Runtime Hook

**In the latest version of Swoole, we add a new feature to make sync network libs to be a coroutine lib with only one step.**

Just call `Swoole\Runtime::enableCoroutine()` method on the top of the script and use php-redis, concurrency 10k requests to read data from Redis takes only 0.1s!

```php
Swoole\Runtime::enableCoroutine();
$s = microtime(true);
for ($c = 100; $c--;) {
    go(function () {
        ($redis = new Redis)->connect('127.0.0.1', 6379);
        for ($n = 100; $n--;) {
            assert($redis->get('awesome') === 'swoole');
        }
    });
}
Swoole\Event::wait();
echo 'use ' . (microtime(true) - $s) . ' s';
```

After you call it, the Swoole kernel will replace the function pointers of streams in ZendVM, if you use `php_stream` based extensions, all socket operations can be dynamically converted to asynchronous IO scheduled by coroutine at runtime.

### How many things you can do in 1s?

Sleep 10k times, read, write, check and delete files 10k times, use PDO and MySQLi to communicate with the database 10k times, create a TCP server and multiple clients to communicate with each other 10k times, create a UDP server and multiple clients to communicate with each other 10k times...Everything works well in one process!

Just see what the Swoole brings, just imagine...

```php
Swoole\Runtime::enableCoroutine();
$s = microtime(true);

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

Swoole\Event::wait();
echo 'use ' . (microtime(true) - $s) . ' s';
```

## ⌛️ Installation

> As with any open source project, Swoole always provides the most reliable stability and the most powerful features in **the latest released version**. Please ensure as much as possible that you are using the latest version.

### Requirements

- Linux, OS X and basic Windows support (thanks to Cygwin)
- PHP 7.0.0 or later (The higher the version, the better the performance.)
- GCC 4.8 or later

### 1. Install via pecl (beginners)

```shell
pecl install swoole
```

### 2. Install from source (recommand)

```shell
git clone https://github.com/swoole/swoole-src.git && \
cd swoole-src && \
phpize && \
./configure && \
make && make install
```

#### Enable extension in PHP

After compiling and installing to the system successfully, you need to add a new line `extension=swoole.so` to `php.ini` to enable Swoole extension.

#### Extra Compiler Configurations

> for example: `./configure --enable-openssl --enable-sockets`

- `--enable-openssl`
- `--enable-sockets`
- `--enable-http2`, `--with-nghttp2-dir=/path/to` (need nghttp2)
- `--enable-mysqlnd` (need mysqlnd)
- `--enable-async-redis`, `--with-hiredis-dir=/path/to` (need hiredis, build-in in v4.2.6 or later)

### Upgrade

>  ⚠️ If you upgrade from source, don't forget to `make clean` before you upgrade your swoole

1. `pecl upgrade swoole`
2. `git pull && cd swoole-src && make clean && make && sudo make install`
3. if you change your PHP version, please re-run `phpize clean && phpize` then try to compile

## 💎 Frameworks & Components

- [**Swoft**](https://github.com/swoft-cloud) is a modern, high-performance AOP and coroutine PHP framework.
- [**Easyswoole**](https://www.easyswoole.com) is a simple, high-performance PHP framework, based on Swoole, which makes using Swoole as easy as `echo "hello world"`.
- [**Saber**](https://github.com/swlib/saber) Is a human-friendly, high-performance HTTP client component that has almost everything you can imagine.

## 🛠 Develop & Discussion

* __中文文档__: <http://wiki.swoole.com>
* __Document__: <https://www.swoole.co.uk/docs>
* __IDE Helper & API__: <https://github.com/swoole/ide-helper>
* __中文社区__: <https://wiki.swoole.com/wiki/page/p-discussion.html>
* __Twitter__: <https://twitter.com/php_swoole>
* __Slack Group__: <https://swoole.slack.com>

## 🍭 Benchmark

+ On the open source [Techempower Web Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r17) Swoole used MySQL database benchmark to rank first, and all performance tests ranked in the first echelon.
+ You can just run [Benchmark Script](./benchmark/benchmark.php) to quickly test the maximum QPS of Swoole-HTTP-Server on your machine.

## 🖊️ Contribution

Your contribution to Swoole development is very welcome!

You may contribute in the following ways:

* [Report issues and feedback](https://github.com/swoole/swoole-src/issues)
* Submit fixes, features via Pull Request
* Write/polish documentation

## ❤️ Contributors

This project exists thanks to all the people who contribute. [[Contributor](https://github.com/swoole/swoole-src/graphs/contributors)].
<a href="https://github.com/swoole/swoole-src/graphs/contributors"><img src="https://opencollective.com/swoole-src/contributors.svg?width=890&button=false" /></a>

## 📃 License

Apache License Version 2.0 see http://www.apache.org/licenses/LICENSE-2.0.html
