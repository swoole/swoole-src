<?php
register_shutdown_function(function () {
    throw new Exception("shutdown 1");
});

register_shutdown_function(function () {
    throw new Exception("shutdown 2");
});

throw new Exception("main");