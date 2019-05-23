<?php

class swoole_curl_handler
{

    private $client;
    private $info;

    public $return_transfer = true;
    public $method;

    function create($url)
    {
        $info = parse_url($url);
        if ($info['scheme'] == 'https') {
            $ssl = true;
        } else {
            $ssl = false;
        }
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
        if ($this->method == 'post') {
            $retval = $this->client->post($this->getUrl());
        } else {
            $retval = $this->client->get($this->getUrl());
        }

        if ($this->return_transfer) {
            return $this->client->body;
        } else {
            echo $this->client->body;
            return $retval;
        }
    }

    function close()
    {
        $this->client = null;
        return true;
    }

    private function getUrl()
    {
        if (empty($this->info['path'])) {
            $url = '/';
        } else {
            $url = $this->info['path'];
        }
        if (!empty($this->info['query'])) {
            $url .= '?' . $this->info['query'];
        }
        if (!empty($this->info['query'])) {
            $url .= '#' . $this->info['fragment'];
        }
        return $url;
    }
}

class swoole_curl_exception extends RuntimeException
{

}

function swoole_curl_init()
{
    return new swoole_curl_handler();
}

function swoole_curl_setopt(swoole_curl_handler $obj, $opt, $value)
{
    switch ($opt) {
        case CURLOPT_URL:
            $obj->create($value);
            break;
        case CURLOPT_RETURNTRANSFER:
            $obj->return_transfer = $value;
            break;
        case CURLOPT_POST:
            $obj->method = 'post';
            break;
        case CURLOPT_HEADER:
            break;
        default:
            throw new swoole_curl_exception("option[$opt] is not supports.");
    }
}

function swoole_curl_exec(swoole_curl_handler $obj)
{
    return $obj->execute();
}


function swoole_curl_close(swoole_curl_handler $obj)
{
    return $obj->close();
}