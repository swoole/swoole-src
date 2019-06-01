<?php

class swoole_curl_handler
{
    /** @var Swoole\Coroutine\Http\Client */
    private $client;
    private $info;
    private $postData;
    private $outputStream;

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

    public $errCode;
    public $errMsg;

    const ERRORS = [
        CURLE_URL_MALFORMAT => 'No URL set!',
    ];

    function create(string $url)
    {
        $info = parse_url($url);
        $proto =  swoole_default_value($info, 'scheme') ;
        if ($proto != 'http' and $proto != 'https') {
            $this->setError(CURLE_UNSUPPORTED_PROTOCOL, "Protocol \"{$proto}\" not supported or disabled in libcurl");
            return;
        }
        $ssl = $proto=== 'https';
        if (empty($info['port'])) {
            $port = $ssl ? 443 : 80;
        } else {
            $port = intval($info['port']);
        }
        $this->info = $info;
        $this->client = new Swoole\Coroutine\Http\Client($info['host'], $port, $ssl);
    }

    function execute()
    {
        $client = $this->client;
        if (!$client) {
            if (!$this->errCode) {
                $this->setError(CURLE_URL_MALFORMAT);
            }
            return false;
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
        if (empty($this->info['path'])) {
            $url = '/';
        } else {
            $url = $this->info['path'];
        }
        if (!empty($this->info['query'])) {
            $url .= '?' . $this->info['query'];
        }
        if (!empty($this->info['fragment'])) {
            $url .= '#' . $this->info['fragment'];
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
                break;
            case CURLOPT_SSL_VERIFYHOST:
                break;
            case CURLOPT_SSL_VERIFYPEER:
                $this->client->set(['ssl_verify_peer' => $value]);
                break;
            case CURLOPT_CONNECTTIMEOUT:
                $this->client->set(['connect_timeout' => $value]);
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
}

class swoole_curl_exception extends swoole_exception
{

}

function swoole_curl_init(): swoole_curl_handler
{
    return new swoole_curl_handler();
}

function swoole_curl_setopt(swoole_curl_handler $obj, $opt, $value): bool
{
    return $obj->setOption($opt, $value);
}

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
