# swoole 2.0 released
Now swoole 2.0 is shipped with original support for coroutine. Implemented by C, swoole is an event-driven, asynchronous and concurrent network engine for PHP. The new swoole 2.0 improves development efficiency extensively -- developers can easily achieve high network throughput by using coroutines in network I/O functions, instead of using trivial `generator`s or async callbacks.

Furthermore, swoole 2.0 enhances the compatibility for PHP 7 without breaking the API backward-compatibility for previous swoole versions. Thus,  users can painlessly upgrade to swoole 2.0.

### Coroutine
With swoole 2.0, developers are able to implement async network I/O without taking care of the low-level details, such as coroutine switch.  We build  coroutine support of swoole 2.0 directly   upon the Zend APIs, which is transparent for developers. Swoole 2.0 is able to switch among all coroutines according to the I/O result and the upper layer does not need to use async callback, which avoids callback hell.  Besides, confusing keywords for coroutine creation like yield are removed.

Now the coroutine component in swoole 2.0 has supported most common protocols including udp, tcp, http, redis and mysql. Private protocols can also be implemented based on udp/tcp.

In addition, developers can also set timeout for IO operations. A corresponding error code will be returned if timeout

Last but not least, developers can use coroutine in both PHP7 and PHP5(>=5.5). PHP7 is recommended because of its high performance.

### Demo
To set up a Http server:

```php
<?php  
$server = new Swoole\Http\Server('127.0.0.1', 9501);

/*
    swoole will initialize a coroutine for every Request event.
 */
$server->on('Request', function($request, $response) {

    $tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    /*
        In the underlining implement of method connect, swoole will 
        save the php context and suspend this coroutine.
        After tcp connection is established, swoole will set the 
        return value and resume this cortoutine.
     */
    $ret = $tcp_cli->connect('127.0.0.1', 9906);
    $tcp_cli ->send('test for the coro');
    /*
        method recv will do the coroutine switching like that of connection.
        swoole will resume this coroutine if server responses nothing after 5s
        and errCode will be set 110 in the example below
     */
    $ret = $tcp_cli->recv(5);
    $tcp_cli->close();

    if ($ret) {
        $response->end(" swoole response is ok");
    }
    else{
        $response->end(" recv failed error : {$client->errCode}");
    }
});

$server->start();
```

UDP server Demo

```php
<?php  
$server = new Swoole\Http\Server('127.0.0.1', 9501);

$server->on('Request', function($request, $response) {

    $tcp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
    $ret = $tcp_cli ->connect('127.0.0.1', 9906);
    $tcp_cli ->send('test for the coro');
    $ret = $tcp_cli ->recv(100);
    $tcp_cli->close();

    if ($ret) {
        $response ->end(" swoole response is ok");
    }
    else{
        $response ->end(" recv failed error : {$client->errCode}");
    }
});

$server->start();
```

**Demos for different kinds of clients:**

1. udp/tcp clieint

```php
$udp_cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);

$ret = $udp_cli ->connect('127.0.0.1', 9906);
$udp_cli ->send('test for the coro');

$ret = $udp_cli ->recv(100);
$udp_cli->close();

if ($ret) {
    $response ->end(" swoole response is ok");
}
else{
    $response ->end(" recv failed error : {$client->errCode}");
}
```

2. http client

```php
$cli = new Swoole\Coroutine\Http\Client('127.0.0.1', 80);
$cli->setHeaders([
    'Host' => "localhost",
    "User-Agent" => 'Chrome/49.0.2587.3',
    'Accept' => 'text/html,application/xhtml+xml,application/xml',
    'Accept-Encoding' => 'gzip',
]);
$cli->set([ 'timeout' => 1]);
$cli->get('/index.php');
echo $cli->body;  
$cli->close();
```
3. redis client
```php
$redis = new Swoole\Coroutine\Redis();
$redis->connect('127.0.0.1', 6379);
$val = $redis->get('key');
```

4. mysql client
```php
$swoole_mysql = new Swoole\Coroutine\MySQL();
$swoole_mysql->connect(['host' => '127.0.0.1', 'user' => 'user', 'password' => 'pass', 'database' => 'test']);
$res = $swoole_mysql->query('select sleep(1)');
```

## Build and Install
* Recommended with PHP7
* Download [swoole-2.0.5](https://github.com/swoole/swoole-src/releases/tag/v2.0.5)

```shell
phpize
./configure 
make -j 4
sudo make install
```
You should add "extension=swoole.so" to php.ini, execute the demo program.

