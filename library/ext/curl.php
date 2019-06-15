<?php

class swoole_curl_handler
{
    private const ERRORS = [
        CURLE_URL_MALFORMAT => 'No URL set!',
    ];

    /** @var Swoole\Coroutine\Http\Client */
    private $client;
    private $info = [
        'url' => '',
        'content_type' => '',
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
        'certinfo' => [],
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
    private $followLocation = false;
    private $maxRedirs;
    private $headerContent = '';
    private $withHeader = false;

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

    public function __construct($url = null)
    {
        if ($url) {
            $this->create($url);
        }
    }

    private function create(string $url): void
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

    public function execute()
    {
        $this->info['redirect_count'] = $this->info['starttransfer_time'] = 0;
        $this->info['redirect_url'] = '';
        $timeBegin = microtime(true);
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
        $isRedirect = false;
        do {
            if ($isRedirect and !$client) {
                $proto = swoole_array_default_value($this->urlInfo, 'scheme');
                if ($proto != 'http' and $proto != 'https') {
                    $this->setError(CURLE_UNSUPPORTED_PROTOCOL, "Protocol \"{$proto}\" not supported or disabled in libcurl");
                    return;
                }
                $ssl = $proto === 'https';
                if (empty($this->urlInfo['port'])) {
                    $port = $ssl ? 443 : 80;
                } else {
                    $port = intval($this->urlInfo['port']);
                }
                $client = new Swoole\Coroutine\Http\Client($this->urlInfo['host'], $port, $ssl);
            }
            /**
             * Http Proxy
             */
            if ($this->proxy) {
                list($proxy_host, $proxy_port) = explode(':', $this->proxy);
                if (!filter_var($proxy_host, FILTER_VALIDATE_IP)) {
                    $ip = \Swoole\Coroutine::gethostbyname($proxy_host);
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
            if ($this->clientOptions) {
                $client->set($this->clientOptions);
            }
            $client->setMethod($this->method);
            /**
             * Upload File
             */
            if ($this->postData and is_array($this->postData)) {
                foreach ($this->postData as $k => $v) {
                    if ($v instanceof CURLFile) {
                        $client->addFile($v->getFilename(), $k, $v->getMimeType() ?: 'application/octet-stream', $v->getPostFilename());
                        unset($this->postData[$k]);
                    }
                }
            }
            /**
             * Post Data
             */
            if ($this->postData) {
                if (is_string($this->postData) and empty($this->headers['Content-Type'])) {
                    $this->headers['Content-Type'] = 'application/x-www-form-urlencoded';
                }
                $client->setData($this->postData);
                $this->postData = [];
            }
            /**
             * Http Header
             */
            $this->headers['Host'] = $this->urlInfo['host'] . (isset($this->urlInfo['port']) ? (':' . $this->urlInfo['port']) : '');
            $client->setHeaders($this->headers);
            /**
             * Execute
             */
            $executeResult = $client->execute($this->getUrl());
            if (!$executeResult) {
                $errCode = $client->errCode;
                if ($errCode == 1 and $client->errMsg == 'Unknown host') {
                    $this->setError(CURLE_COULDNT_RESOLVE_HOST, 'Could not resolve host: ' . $client->host);
                }
                $this->info['total_time'] = microtime(true) - $timeBegin;
                return false;
            }
            if ($client->statusCode >= 300 and $client->statusCode < 400 and isset($client->headers['location'])) {
                $redirectParsedUrl = $this->getRedirectUrl($client->headers['location']);
                $redirectUrl = $this->unparseUrl($redirectParsedUrl);
                if ($this->followLocation and (null === $this->maxRedirs or $this->info['redirect_count'] < $this->maxRedirs)) {
                    $isRedirect = true;
                    if (0 === $this->info['redirect_count']) {
                        $this->info['starttransfer_time'] = microtime(true) - $timeBegin;
                        $redirectBeginTime = microtime(true);
                    }
                    // force GET
                    if (in_array($client->statusCode, [301, 302, 303])) {
                        $this->method = 'GET';
                    }
                    if ($this->urlInfo['host'] !== $redirectParsedUrl['host'] or ($this->urlInfo['port'] ?? null) !== ($redirectParsedUrl['port'] ?? null) or $this->urlInfo['scheme'] !== $redirectParsedUrl['scheme']) {
                        // If host, port, and scheme are the same, reuse $client. Otherwise, release the old $client
                        $client = null;
                    }
                    $this->urlInfo = $redirectParsedUrl;
                    $this->info['url'] = $redirectUrl;
                    $this->info['redirect_count']++;
                } else {
                    $this->info['redirect_url'] = $redirectUrl;
                    break;
                }
            } else {
                break;
            }
        } while (true);
        $this->info['total_time'] = microtime(true) - $timeBegin;
        $this->info['http_code'] = $client->statusCode;
        $this->info['content_type'] = $client->headers['content-type'] ?? '';
        $this->info['size_download'] = $this->info['download_content_length'] = strlen($client->body);;
        $this->info['speed_download'] = 1 / $this->info['total_time'] * $this->info['size_download'];
        if (isset($redirectBeginTime)) {
            $this->info['redirect_time'] = microtime(true) - $redirectBeginTime;
        }

        if ($client->headers) {
            $cb = $this->headerFunction;
            $headerContent = '';
            if ($client->statusCode > 0) {
                $row = 'HTTP/1.1 ' . $client->statusCode . ' ' . swoole_http_status_code::getReasonPhrase($client->statusCode) . "\r\n";
                if($cb) {
                    $cb($this, $row);
                }
                $headerContent .= $row;
            }
            foreach ($client->headers as $k => $v) {
                $row = "$k: $v\r\n";
                if($cb) {
                    $cb($this, $row);
                }
                $headerContent .= $row;
            }
            $headerContent .= "\r\n";
            $this->info['header_size'] = strlen($headerContent);
            if($cb) {
                $cb($this, '');
            }
        } else {
            $this->info['header_size'] = 0;
        }

        if ($client->body and $this->readFunction) {
            $cb = $this->readFunction;
            $cb($this, $this->outputStream, strlen($client->body));
        }

        if($this->withHeader) {
            $transfer = $headerContent . $client->body;
        } else {
            $transfer = $client->body;
        }

        if ($this->returnTransfer) {
            return $transfer;
        } else {
            if ($this->outputStream) {
                return fwrite($this->outputStream, $transfer) === strlen($transfer);
            } else {
                echo $transfer;
            }
            return true;
        }
    }

    public function close(): void
    {
        $this->client = null;
    }

    private function setError($code, $msg = ''): void
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
    public function setOption(int $opt, $value): bool
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
                $this->postData = $value;
                $this->method = 'POST';
                break;
            /**
             * Upload
             */
            case CURLOPT_SAFE_UPLOAD:
                if (!$value) {
                    trigger_error('curl_setopt(): Disabling safe uploads is no longer supported', E_USER_WARNING);
                }
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
                $this->clientOptions['connect_timeout'] = $value / 1000;
                break;
            case CURLOPT_TIMEOUT:
                $this->clientOptions['timeout'] = $value;
                break;
            case CURLOPT_TIMEOUT_MS:
                $this->clientOptions['timeout'] = $value / 1000;
                break;
            case CURLOPT_FILE:
                $this->outputStream = $value;
                break;
            case CURLOPT_HEADER:
                $this->withHeader = $value;
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
            case CURLOPT_USERPWD:
                $this->headers['Authorization'] = 'Basic ' . base64_encode($value);
                break;
            case CURLOPT_FOLLOWLOCATION:
                $this->followLocation = $value;
                break;
            case CURLOPT_MAXREDIRS:
                $this->maxRedirs = $value;
                break;
            default:
                throw new swoole_curl_exception("option[{$opt}] not supported");
        }
        return true;
    }

    public function reset(): void
    {
    }

    public function getInfo()
    {
        return $this->info;
    }

    private function unparseUrl(array $parsedUrl): string
    {
        $scheme   = ($parsedUrl['scheme'] ?? 'http') . '://';
        $host     = $parsedUrl['host'] ?? '';
        $port     = isset($parsedUrl['port']) ? ':' . $parsedUrl['port'] : '';
        $user     = $parsedUrl['user'] ?? '';
        $pass     = isset($parsedUrl['pass']) ? ':' . $parsedUrl['pass']  : '';
        $pass     = ($user or $pass) ? "$pass@" : '';
        $path     = $parsedUrl['path'] ?? '';
        $query    = (isset($parsedUrl['query']) and '' !== $parsedUrl['query']) ? '?' . $parsedUrl['query'] : '';
        $fragment = isset($parsedUrl['fragment']) ? '#' . $parsedUrl['fragment'] : '';
        return $scheme . $user . $pass . $host . $port . $path . $query . $fragment;
    }

    private function getRedirectUrl(string $location): array
    {
        $uri = parse_url($location);
        if (isset($uri['host'])) {
            $redirectUri = $uri;
        } else {
            if (!isset($location[0])) {
                return [];
            }
            $redirectUri = $this->urlInfo;
            $redirectUri['query'] = '';
            if ('/' === $location[0]) {
                $redirectUri['path'] = $location;
            } else {
                $path = dirname($redirectUri['path'] ?? '');
                if ('.' === $path) {
                    $path = '/';
                }
                if (isset($location[1]) and './' === substr($location, 0, 2)) {
                    $location = substr($location, 2);
                }
                $redirectUri['path'] = $path . $location;
            }
            foreach ($uri as $k => $v) {
                if (!in_array($k, ['path', 'query'])) {
                    $redirectUri[$k] = $v;
                }
            }
        }
        return $redirectUri;
    }
}

class swoole_curl_exception extends swoole_exception
{

}

abstract class swoole_http_status_code
{
    const CONTINUE = 100;
    const SWITCHING_PROTOCOLS = 101;
    const PROCESSING = 102;
    const OK = 200;
    const CREATED = 201;
    const ACCEPTED = 202;
    const NON_AUTHORITATIVE_INFORMATION = 203;
    const NO_CONTENT = 204;
    const RESET_CONTENT = 205;
    const PARTIAL_CONTENT = 206;
    const MULTI_STATUS = 207;
    const ALREADY_REPORTED = 208;
    const IM_USED = 226;
    const MULTIPLE_CHOICES = 300;
    const MOVED_PERMANENTLY = 301;
    const FOUND = 302;
    const SEE_OTHER = 303;
    const NOT_MODIFIED = 304;
    const USE_PROXY = 305;
    const SWITCH_PROXY = 306;
    const TEMPORARY_REDIRECT = 307;
    const PERMANENT_REDIRECT = 308;
    const BAD_REQUEST = 400;
    const UNAUTHORIZED = 401;
    const PAYMENT_REQUIRED = 402;
    const FORBIDDEN = 403;
    const NOT_FOUND = 404;
    const METHOD_NOT_ALLOWED = 405;
    const NOT_ACCEPTABLE = 406;
    const PROXY_AUTHENTICATION_REQUIRED = 407;
    const REQUEST_TIME_OUT = 408;
    const CONFLICT = 409;
    const GONE = 410;
    const LENGTH_REQUIRED = 411;
    const PRECONDITION_FAILED = 412;
    const REQUEST_ENTITY_TOO_LARGE = 413;
    const REQUEST_URI_TOO_LARGE = 414;
    const UNSUPPORTED_MEDIA_TYPE = 415;
    const REQUESTED_RANGE_NOT_SATISFIABLE = 416;
    const EXPECTATION_FAILED = 417;
    const MISDIRECTED_REQUEST = 421;
    const UNPROCESSABLE_ENTITY = 422;
    const LOCKED = 423;
    const FAILED_DEPENDENCY = 424;
    const UNORDERED_COLLECTION = 425;
    const UPGRADE_REQUIRED = 426;
    const PRECONDITION_REQUIRED = 428;
    const TOO_MANY_REQUESTS = 429;
    const REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
    const UNAVAILABLE_FOR_LEGAL_REASONS = 451;
    const INTERNAL_SERVER_ERROR = 500;
    const NOT_IMPLEMENTED = 501;
    const BAD_GATEWAY = 502;
    const SERVICE_UNAVAILABLE = 503;
    const GATEWAY_TIME_OUT = 504;
    const HTTP_VERSION_NOT_SUPPORTED = 505;
    const VARIANT_ALSO_NEGOTIATES = 506;
    const INSUFFICIENT_STORAGE = 507;
    const LOOP_DETECTED = 508;
    const NOT_EXTENDED = 510;
    const NETWORK_AUTHENTICATION_REQUIRED = 511;

    private static $reasonPhrases = [
        self::CONTINUE => 'Continue',
        self::SWITCHING_PROTOCOLS => 'Switching Protocols',
        self::PROCESSING => 'Processing',
        self::OK => 'OK',
        self::CREATED => 'Created',
        self::ACCEPTED => 'Accepted',
        self::NON_AUTHORITATIVE_INFORMATION => 'Non-Authoritative Information',
        self::NO_CONTENT => 'No Content',
        self::RESET_CONTENT => 'Reset Content',
        self::PARTIAL_CONTENT => 'Partial Content',
        self::MULTI_STATUS => 'Multi-status',
        self::ALREADY_REPORTED => 'Already Reported',
        self::IM_USED => 'IM Used',
        self::MULTIPLE_CHOICES => 'Multiple Choices',
        self::MOVED_PERMANENTLY => 'Moved Permanently',
        self::FOUND => 'Found',
        self::SEE_OTHER => 'See Other',
        self::NOT_MODIFIED => 'Not Modified',
        self::USE_PROXY => 'Use Proxy',
        self::SWITCH_PROXY => 'Switch Proxy',
        self::TEMPORARY_REDIRECT => 'Temporary Redirect',
        self::PERMANENT_REDIRECT => 'Permanent Redirect',
        self::BAD_REQUEST => 'Bad Request',
        self::UNAUTHORIZED => 'Unauthorized',
        self::PAYMENT_REQUIRED => 'Payment Required',
        self::FORBIDDEN => 'Forbidden',
        self::NOT_FOUND => 'Not Found',
        self::METHOD_NOT_ALLOWED => 'Method Not Allowed',
        self::NOT_ACCEPTABLE => 'Not Acceptable',
        self::PROXY_AUTHENTICATION_REQUIRED => 'Proxy Authentication Required',
        self::REQUEST_TIME_OUT => 'Request Time-out',
        self::CONFLICT => 'Conflict',
        self::GONE => 'Gone',
        self::LENGTH_REQUIRED => 'Length Required',
        self::PRECONDITION_FAILED => 'Precondition Failed',
        self::REQUEST_ENTITY_TOO_LARGE => 'Request Entity Too Large',
        self::REQUEST_URI_TOO_LARGE => 'Request-URI Too Large',
        self::UNSUPPORTED_MEDIA_TYPE => 'Unsupported Media Type',
        self::REQUESTED_RANGE_NOT_SATISFIABLE => 'Requested range not satisfiable',
        self::EXPECTATION_FAILED => 'Expectation Failed',
        self::MISDIRECTED_REQUEST => 'Unprocessable Entity',
        self::UNPROCESSABLE_ENTITY => 'Unprocessable Entity',
        self::LOCKED => 'Locked',
        self::FAILED_DEPENDENCY => 'Failed Dependency',
        self::UNORDERED_COLLECTION => 'Unordered Collection',
        self::UPGRADE_REQUIRED => 'Upgrade Required',
        self::PRECONDITION_REQUIRED => 'Precondition Required',
        self::TOO_MANY_REQUESTS => 'Too Many Requests',
        self::REQUEST_HEADER_FIELDS_TOO_LARGE => 'Request Header Fields Too Large',
        self::UNAVAILABLE_FOR_LEGAL_REASONS => 'Unavailable For Legal Reasons',
        self::INTERNAL_SERVER_ERROR => 'Internal Server Error',
        self::NOT_IMPLEMENTED => 'Not Implemented',
        self::BAD_GATEWAY => 'Bad Gateway',
        self::SERVICE_UNAVAILABLE => 'Service Unavailable',
        self::GATEWAY_TIME_OUT => 'Gateway Time-out',
        self::HTTP_VERSION_NOT_SUPPORTED => 'HTTP Version not supported',
        self::VARIANT_ALSO_NEGOTIATES => 'Variant Also Negotiates',
        self::INSUFFICIENT_STORAGE => 'Insufficient Storage',
        self::LOOP_DETECTED => 'Loop Detected',
        self::NOT_EXTENDED => 'Not Extended',
        self::NETWORK_AUTHENTICATION_REQUIRED => 'Network Authentication Required',
    ];

    /**
     * 根据状态码获取原因短语
     * @param int $value
     * @return string
     */
    public static function getReasonPhrase($value)
    {
        return isset(static::$reasonPhrases[$value]) ? static::$reasonPhrases[$value] : '';
    }
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
            case CURLINFO_REDIRECT_COUNT:
                return $info['redirect_count'];
            case CURLINFO_REDIRECT_URL:
                return $info['redirect_url'];
            case CURLINFO_TOTAL_TIME:
                return $info['total_time'];
            case CURLINFO_STARTTRANSFER_TIME:
                return $info['starttransfer_time'];
            case CURLINFO_SIZE_DOWNLOAD:
                return $info['size_download'];
            case CURLINFO_SPEED_DOWNLOAD:
                return $info['speed_download'];
            case CURLINFO_REDIRECT_TIME:
                return $info['redirect_time'];
            case CURLINFO_HEADER_SIZE:
                return $info['header_size'];
            default:
                return null;
        }
    } else {
        return $info;
    }
}
