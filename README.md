<h2 align=center>
<img width="200" height="120" alt="Swoole Logo" src="docs/swoole-logo.svg" /> <br />
    Swoole is an event-driven, asynchronous, coroutine-based concurrency library with high performance for PHP.
</h2>

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

## ⚙️ Quick Start

Run Swoole program by [Docker](https://github.com/swoole/docker-swoole)

```bash
docker run --rm phpswoole/swoole "php --ri swoole"
```

> For details on how to use it, see: [How to Use This Image](https://github.com/swoole/docker-swoole#how-to-use-this-image).

### HTTP Service
```php
$http = new Swoole\Http\Server('127.0.0.1', 9501);
$http->set(['hook_flags' => SWOOLE_HOOK_ALL]);

$http->on('request', function ($request, $response) {
    $result = [];
    Co::join([
        go(function () use (&$result) {
            $result['google'] = file_get_contents("https://www.google.com/");
        }),
        go(function () use (&$result) {
            $result['taobao'] = file_get_contents("https://www.taobao.com/");
        })
    ]);
    $response->end(json_encode($result));
});

$http->start();
```

### Concurrency
```php
Co\run(function() {
    Co\go(function() {
        while(1) {
            sleep(1);
            $fp = stream_socket_client("tcp://127.0.0.1:8000", $errno, $errstr, 30);
            echo fread($fp, 8192), PHP_EOL;
        }
    });

    Co\go(function() {
        $fp = stream_socket_server("tcp://0.0.0.0:8000", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
        while(1) {
            $conn = stream_socket_accept($fp);
            fwrite($conn, 'The local time is ' . date('n/j/Y g:i a'));
        }
    });

    Co\go(function() {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379);
        while(true) {
            $redis->subscribe(['test'], function ($instance, $channelName, $message) {
                echo 'New redis message: '.$channelName, "==>", $message, PHP_EOL;
            });
        }
    });

    Co\go(function() {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379);
        $count = 0;
        while(true) {
            sleep(2);
            $redis->publish('test','hello, world, count='.$count++);
        }
    });
});
```

## Runtime Hook

**Swoole hooks the blocking io function of PHP at the `bottom layer` and `automatically` converts it to a non-blocking function, so that these functions can be called concurrently in coroutines.**

### Supported extension/functions

* `ext-curl` (Support `symfony` and `guzzle`)
* `ext-redis`
* `ext-mysqli`
* `ext-pdo_mysql`
* `ext-pdo_pgsql`
* `ext-pdo_sqlite`
* `ext-pdo_oracle`
* `ext-pdo_odbc`
* `stream functions` (e.g. `stream_socket_client`/`stream_socket_server`), Supports `TCP`/`UDP`/`UDG`/`Unix`/`SSL/TLS`/`FileSystem API`/`Pipe`
* `ext-sockets`
* `ext-soap`
* `sleep`/`usleep`/`time_sleep_until`
* `proc_open`
* `gethostbyname`/`shell_exec`/`exec`
* `fread`/`fopen`/`fsockopen`/`fwrite`/`flock`


## 🛠 Develop & Discussion

+ __IDE Helper & API__: <https://github.com/swoole/ide-helper>
+ __Twitter__: <https://twitter.com/phpswoole>
+ __Discord__: <https://discord.swoole.dev>
+ __中文文档__: <https://wiki.swoole.com>
+ __中文社区__: <https://wiki.swoole.com/#/other/discussion>

## 💎 Awesome Swoole
Project [Awesome Swoole](https://github.com/swoole/awesome-swoole) maintains a curated list of awesome things related to Swoole, including

* Swoole-based frameworks and libraries.
* Packages to integrate Swoole with popular PHP frameworks, including Laravel, Symfony, Slim, and Yii.
* Books, videos, and other learning materials about Swoole.
* Debugging, profiling, and testing tools for developing Swoole-based applications.
* Coroutine-friendly packages and libraries.
* Other Swoole related projects and resources.

## ✨ Event-based

The network layer in Swoole is event-based and takes full advantage of the underlying epoll/kqueue implementation, making it really easy to serve millions of requests.

Swoole 4.x uses a brand new engine kernel and now it has a full-time developer team, so we are entering an unprecedented period in PHP history which offers a unique possibility for rapid evolution in performance.

## ⚡ Coroutine

Swoole 4.x or later supports the built-in coroutine with high availability, and you can use fully synchronized code to implement asynchronous performance. PHP code without any additional keywords, the underlying automatic coroutine-scheduling.

Developers can understand coroutines as ultra-lightweight threads, and you can easily create thousands of coroutines in a single process.

### MySQL

Concurrency 10K requests to read data from MySQL takes only 0.2s!

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

### Mixed server

You can create multiple services on the single event loop: TCP, HTTP, Websocket and HTTP2, and easily handle thousands of requests.

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

### Coroutine clients

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

#### Producer and consumers

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
#### The way of coroutine

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

## 🔥 Amazing runtime hooks

**As of Swoole v4.1.0, we added the ability to transform synchronous PHP network libraries into co-routine libraries using a single line of code.**

Simply call the `Swoole\Runtime::enableCoroutine()` method at the top of your script. In the sample below we connect to php-redis and concurrently read 10k requests in 0.1s:

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

By calling this method, the Swoole kernel replaces ZendVM stream function pointers. If you use `php_stream` based extensions, all socket operations can be dynamically converted to be asynchronous IO scheduled by coroutine at runtime!

### How many things you can do in 1s?

Sleep 10K times, read, write, check and delete files 10K times, use PDO and MySQLi to communicate with the database 10K times, create a TCP server and multiple clients to communicate with each other 10K times, create a UDP server and multiple clients to communicate with each other 10K times... Everything works well in one process!

Just see what the Swoole brings, just imagine...

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

    // 10K file read and write
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

    // 10K pdo and mysqli read
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

    // php_stream tcp server & client with 12.8K requests in single process
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

    // udp server & client with 12.8K requests in single process
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

## ⌛️ Installation

> As with any open source project, Swoole always provides the most reliable stability and the most powerful features in **the latest released version**. Please ensure as much as possible that you are using the latest version.

### Compiling requirements

+ Linux, OS X or Cygwin, WSL
+ PHP 7.2.0 or later (The higher the version, the better the performance.)
+ GCC 4.8 or later

### 1. Install via PECL (beginners)

```shell
pecl install swoole
```

### 2. Install from source (recommended)

Please download the source packages from [Releases](https://github.com/swoole/swoole-src/releases) or:

```shell
git clone https://github.com/swoole/swoole-src.git && \
cd swoole-src
```

Compile and install at the source folder:

```shell
phpize && \
./configure && \
make && make install
```

#### Enable extension in PHP

After compiling and installing to the system successfully, you have to add a new line `extension=swoole.so` to `php.ini` to enable Swoole extension.

#### Extra compiler configurations

> for example: `./configure --enable-openssl --enable-sockets`

+ `--enable-openssl` or `--with-openssl-dir=DIR`
+ `--enable-sockets`
+ `--enable-mysqlnd` (need mysqlnd, it just for supporting `$mysql->escape` method)
+ `--enable-swoole-curl`

### Upgrade

>  ⚠️ If you upgrade from source, don't forget to `make clean` before you upgrade your swoole

1. `pecl upgrade swoole`
2. `cd swoole-src && git pull && make clean && make && sudo make install`
3. if you change your PHP version, please re-run `phpize clean && phpize` then try to compile

### Major change since version 4.3.0

Async clients and API are moved to a separate PHP extension `swoole_async` since version 4.3.0, install `swoole_async`:

```shell
git clone https://github.com/swoole/ext-async.git
cd ext-async
phpize
./configure
make -j 4
sudo make install
```

Enable it by adding a new line `extension=swoole_async.so` to `php.ini`.

## 🍭 Benchmark

+ On the open source [Techempower Web Framework benchmarks](https://www.techempower.com/benchmarks/#section=data-r17) Swoole used MySQL database benchmark to rank first, and all performance tests ranked in the first echelon.
+ You can just run [Benchmark Script](https://github.com/swoole/benchmark/blob/master/benchmark.php) to quickly test the maximum QPS of Swoole-HTTP-Server on your machine.

## 🔰️ Security issues

Security issues should be reported privately, via email, to the Swoole develop team [team@swoole.com](mailto:team@swoole.com). You should receive a response within 24 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## 🖊️ Contribution

Your contribution to Swoole development is very welcome!

You may contribute in the following ways:

* [Report issues and feedback](https://github.com/swoole/swoole-src/issues)
* Submit fixes, features via Pull Request
* Write/polish documentation

## ❤️ Contributors

This project exists thanks to all the people who contribute. [[Contributors](https://github.com/swoole/swoole-src/graphs/contributors)].
<a href="https://github.com/swoole/swoole-src/graphs/contributors"><img src="https://opencollective.com/swoole-src/contributors.svg?width=890&button=false" /></a>

## 🎙️ Official Evangelist

[Demin](https://deminy.in) has been playing with PHP since 2000, focusing on building high-performance, secure web services. He is an occasional conference speaker on PHP and Swoole, and has been working for companies in the states like eBay, Visa and Glu Mobile for years. You may find Demin on [Twitter](https://twitter.com/deminy) or [GitHub](https://github.com/deminy).

## 📃 License

Apache License Version 2.0 see http://www.apache.org/licenses/LICENSE-2.0.html
