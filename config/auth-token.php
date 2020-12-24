<?php


return [
    'lifetime' => [
        'expired' => 7 * 24 * 3600,  // 7 days
        'refresh' => 3600,           // 1 hour
    ],

    'token_field' => [
        'header' => 'Authorization',
        'cookie' => 'X-Auth-Token',
    ],

    'autoload_middleware' => true,
];
