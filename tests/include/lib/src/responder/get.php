<?php
$test = isset($_GET['test']) ? $_GET['test'] : null;
switch ($test) {
    case 'post':
        var_dump($_POST);
        break;
    case 'getpost':
        var_dump($_GET);
        var_dump($_POST);
        break;
    case 'referer':
        echo $_SERVER['HTTP_REFERER'];
        break;
    case 'auto_referer':
        header('HTTP/1.1 302 Found');
        header('location:get.php?test=referer');
        exit;
        break;
    case 'useragent':
        echo $_SERVER['HTTP_USER_AGENT'];
        break;
    case 'httpversion':
        echo $_SERVER['SERVER_PROTOCOL'];
        break;
    case 'cookie':
        echo $_COOKIE['foo'];
        break;
    case 'cookie_get':
        echo json_encode($_COOKIE);
        break;
    case 'cookie_set':
        echo json_encode(setcookie($_GET['cookie_name'], $_GET['cookie_value'], $_GET['cookie_expire']));
        break;
    case 'encoding':
        echo $_SERVER['HTTP_ACCEPT_ENCODING'];
        break;
    case 'contenttype':
        header('Content-Type: text/plain;charset=utf-8');
        break;
    case 'file':
        if (isset($_FILES['file'])) {
            echo $_FILES['file']['name'] . '|' . $_FILES['file']['type'] . '|' . $_FILES['file']['size'];
        }
        break;
    case 'method':
        echo $_SERVER['REQUEST_METHOD'];
        break;
    case 'redirect_301':
        header('HTTP/1.1 301 Moved Permanently');
        header('location:get.php?test=getpost');
        exit;
        break;
    case 'redirect_302':
        header('HTTP/1.1 302 Found');
        header('location:get.php?test=getpost');
        exit;
        break;
    case 'redirect_307':
        header('HTTP/1.1 307 Temporary Redirect');
        header('location:get.php?test=getpost');
        exit;
        break;
    case 'redirect_308':
        header('HTTP/1.1 308 Permanent Redirect');
        header('location:get.php?test=getpost');
        exit;
        break;
    case 'header_body':
        header('abc: 123');
        echo "a\nb\nc";
        break;
    case 'input':
        echo file_get_contents('php://input');
        break;
    default:
        echo "Hello World!\n";
        echo "Hello World!";
        break;
}
