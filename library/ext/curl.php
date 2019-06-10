<?php

class swoole_curl_handler
{
    /** @var Swoole\Coroutine\Http\Client */
    private $client;
    private $info = [
        'url' => '',
        'content_type' => NULL,
        'http_code' => 0,
        'header_size' => 0,
        'request_size' => 0,
        'filetime' => -1,
        'ssl_verify_result' => 0,
        'redirect_count' => 0,
        'total_time' => 5.3E-5,
        'namelookup_time' => 0.0,
        'connect_time' => 0.0,
        'pretransfer_time' => 0.0,
        'size_upload' => 0.0,
        'size_download' => 0.0,
        'speed_download' => 0.0,
        'speed_upload' => 0.0,
        'download_content_length' => -1.0,
        'upload_content_length' => -1.0,
        'starttransfer_time' => 0.0,
        'redirect_time' => 0.0,
        'redirect_url' => '',
        'primary_ip' => '',
        'certinfo' =>
            array(),
        'primary_port' => 0,
        'local_ip' => '',
        'local_port' => 0,
        'http_version' => 0,
        'protocol' => 0,
        'ssl_verifyresult' => 0,
        'scheme' => '',
    ];
    private $urlInfo;
    private $postData;
    private $outputStream;
    private $proxy;
    private $clientOptions = [];

    /** @var callable */
    private $headerFunction;
    /** @var callable */
    private $readFunction;
    /** @var callable */
    private $writeFunction;
    /** @var callable */
    private $progressFunction;

    public $returnTransfer = false;
    public $method = 'GET';
    public $headers = [];

    public $errCode = 0;
    public $errMsg = '';

    const ERRORS = [
        CURLE_URL_MALFORMAT => 'No URL set!',
    ];

    function __construct($url = null)
    {
        if ($url) {
            $this->create($url);
        }
    }

    function create(string $url)
    {
        if (!swoole_string($url)->contains('://')) {
            $url = 'http://' . $url;
        }
        $this->info['url'] = $url;
        $info = parse_url($url);
        $proto = swoole_array_default_value($info, 'scheme');
        if ($proto != 'http' and $proto != 'https') {
            $this->setError(CURLE_UNSUPPORTED_PROTOCOL, "Protocol \"{$proto}\" not supported or disabled in libcurl");
            return;
        }
        $ssl = $proto === 'https';
        if (empty($info['port'])) {
            $port = $ssl ? 443 : 80;
        } else {
            $port = intval($info['port']);
        }
        $this->urlInfo = $info;
        $this->client = new Swoole\Coroutine\Http\Client($info['host'], $port, $ssl);
    }

    function execute()
    {
        /**
         * Socket
         */
        $client = $this->client;
        if (!$client) {
            if (!$this->errCode) {
                $this->setError(CURLE_URL_MALFORMAT);
            }
            return false;
        }
        /**
         * Http Proxy
         */
        if ($this->proxy) {
            list($proxy_host, $proxy_port) = explode(':', $this->proxy);
            if (!filter_var($proxy_host, FILTER_VALIDATE_IP)) {
                $ip = Co::gethostbyname($proxy_host);
                if (!$ip) {
                    $this->setError(CURLE_COULDNT_RESOLVE_PROXY, 'Could not resolve proxy: ' . $proxy_host);
                    return false;
                } else {
                    $proxy_host = $ip;
                }
            }
            $client->set(['http_proxy_host' => $proxy_host, 'http_proxy_port' => $proxy_port]);
        }
        /**
         * Client Options
         */
        if($this->clientOptions)
        {
            $client->set($this->clientOptions);
        }
        $client->setMethod($this->method);
        if ($this->headers) {
            $client->setHeaders($this->headers);
        }
        if ($this->postData) {
            $client->setData($this->postData);
        }
        if (!$client->execute($this->getUrl())) {

            $errCode = $this->client->errCode;
            if ($errCode == 1 and $this->client->errMsg == 'Unknown host') {
                $this->setError(CURLE_COULDNT_RESOLVE_HOST, 'Could not resolve host: ' . $this->client->host);
            }
            return false;
        }

        $this->info['http_code'] = $client->statusCode;
        $this->info['content_type'] = $client->headers['content-type'];

        if ($client->headers and $this->headerFunction) {
            $cb = $this->headerFunction;
            if ($client->statusCode === 200) {
                $cb($this, "HTTP/1.1 200 OK\r\n");
            }
            foreach ($client->headers as $k => $v) {
                $cb($this, "$k: $v\r\n");
            }
            $cb($this, '');
        }

        if ($client->body and $this->readFunction) {
            $cb = $this->readFunction;
            $cb($this, $this->outputStream, strlen($client->body));
        }
        if ($this->returnTransfer) {
            return $client->body;
        } else {
            if ($this->outputStream) {
                return fwrite($this->outputStream, $client->body) === strlen($client->body);
            } else {


                echo $client->body;
            }
            return true;
        }
    }

    function close(): void
    {
        $this->client = null;
    }

    function setError($code, $msg = '')
    {
        $this->errCode = $code;
        $this->errMsg = $msg ? $msg : self::ERRORS[$code];
    }

    private function getUrl(): string
    {
        if (empty($this->urlInfo['path'])) {
            $url = '/';
        } else {
            $url = $this->urlInfo['path'];
        }
        if (!empty($this->urlInfo['query'])) {
            $url .= '?' . $this->urlInfo['query'];
        }
        if (!empty($this->urlInfo['fragment'])) {
            $url .= '#' . $this->urlInfo['fragment'];
        }
        return $url;
    }

    /**
     * @param int $opt
     * @param $value
     * @return bool
     * @throws swoole_curl_exception
     */
    function setOption(int $opt, $value): bool
    {
        switch ($opt) {
            /**
             * Basic
             */
            case CURLOPT_URL:
                $this->create($value);
                break;
            case CURLOPT_RETURNTRANSFER:
                $this->returnTransfer = $value;
                break;
            case CURLOPT_ENCODING:
                if (empty($value)) {
                    $value = 'gzip';
                }
                $this->headers['Accept-Encoding'] = $value;
                break;
            case CURLOPT_PROXY:
                $this->proxy = $value;
                break;
            /**
             * Http Post
             */
            case CURLOPT_POST:
                $this->method = 'POST';
                break;
            case CURLOPT_POSTFIELDS:
                $this->headers['Content-Type'] = 'application/x-www-form-urlencoded';
                $this->postData = $value;
                break;

            /**
             * Http Header
             */
            case CURLOPT_HTTPHEADER:
                if (!is_array($value) and !($value instanceof Iterator)) {
                    trigger_error('swoole_curl_setopt(): You must pass either an object or an array with the CURLOPT_HTTPHEADER argument', E_USER_WARNING);
                    return false;
                }
                foreach ($value as $header) {
                    list($k, $v) = explode(':', $header);
                    $v = trim($v);
                    if ($v) {
                        $this->headers[$k] = $v;
                    }
                }
                break;
            case CURLOPT_REFERER:
                $this->headers['Referer'] = $value;
                break;

            case CURLOPT_USERAGENT:
                $this->headers['User-Agent'] = $value;
                break;

            case CURLOPT_CUSTOMREQUEST:
                break;
            case CURLOPT_PROTOCOLS:
                if ($value > 3) {
                    throw new swoole_curl_exception("option[{$opt}={$value}] not supported");
                }
                break;
            case CURLOPT_HTTP_VERSION:
                if ($value != CURL_HTTP_VERSION_1_1) {
                    trigger_error("swoole_curl: http version[{$value}] not supported", E_USER_WARNING);
                }
                break;
            /**
             * Http Cookie
             */
            case CURLOPT_COOKIE:
                $this->headers['Cookie'] = $value;
                break;
            case CURLOPT_SSL_VERIFYHOST:
                break;
            case CURLOPT_SSL_VERIFYPEER:
                $this->clientOptions['ssl_verify_peer'] = $value;
                break;
            case CURLOPT_CONNECTTIMEOUT:
                $this->clientOptions['connect_timeout'] = $value;
                break;
            case CURLOPT_CONNECTTIMEOUT_MS:
                $this->clientOptions['connect_timeout'] = $value * 1000;
                break;
            case CURLOPT_TIMEOUT:
                $this->clientOptions['timeout'] = $value;
                break;
            case CURLOPT_TIMEOUT_MS:
                $this->clientOptions['timeout'] = $value * 1000;
                break;
            case CURLOPT_FILE:
                $this->outputStream = $value;
                break;
            case CURLOPT_HEADER:
                break;
            case CURLOPT_HEADERFUNCTION:
                $this->headerFunction = $value;
                break;
            case CURLOPT_READFUNCTION:
                $this->readFunction = $value;
                break;
            case CURLOPT_WRITEFUNCTION:
                $this->writeFunction = $value;
                break;
            case CURLOPT_PROGRESSFUNCTION:
                $this->progressFunction = $value;
                break;
            default:
                throw new swoole_curl_exception("option[{$opt}] not supported");
        }
        return true;
    }

    function reset(): void
    {
        $this->client->body = '';
    }

    public function getInfo()
    {
        return $this->info;
    }
}

class swoole_curl_exception extends swoole_exception
{

}

function swoole_curl_init($url = null): swoole_curl_handler
{
    return new swoole_curl_handler($url);
}

/**
 * @param swoole_curl_handler $obj
 * @param $opt
 * @param $value
 * @return bool
 * @throws swoole_curl_exception
 */
function swoole_curl_setopt(swoole_curl_handler $obj, $opt, $value): bool
{
    return $obj->setOption($opt, $value);
}

/**
 * @param swoole_curl_handler $obj
 * @param $array
 * @return bool
 * @throws swoole_curl_exception
 */
function swoole_curl_setopt_array(swoole_curl_handler $obj, $array): bool
{
    foreach ($array as $k => $v) {
        if ($obj->setOption($k, $v) === false) {
            return false;
        }
    }
    return true;
}

function swoole_curl_exec(swoole_curl_handler $obj)
{
    return $obj->execute();
}

function swoole_curl_close(swoole_curl_handler $obj): void
{
    $obj->close();
}

function swoole_curl_error(swoole_curl_handler $obj): string
{
    return $obj->errMsg;
}

function swoole_curl_errno(swoole_curl_handler $obj): int
{
    return $obj->errCode;
}

function swoole_curl_reset(swoole_curl_handler $obj): void
{
    $obj->reset();
}

function swoole_curl_getinfo(swoole_curl_handler $obj, int $opt = 0)
{
    $info = $obj->getInfo();
    if ($opt) {
        switch ($opt) {
            case CURLINFO_EFFECTIVE_URL:
                return $info['url'];
            case CURLINFO_HTTP_CODE:
                return $info['http_code'];
            case CURLINFO_CONTENT_TYPE:
                return $info['content_type'];
        }
    } else {
        return $info;
    }
}
