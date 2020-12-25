<?php


return [
    'lifetime' => [
        'expired' => 7 * 24 * 3600,  // Lifetime of token before expired. Default 7 days
        'refresh' => 3600,           // The minimum seconds before changing the token. Default 1 hour
    ],

    'token_field' => [
        'header' => 'Authorization', // Set [false/null/empty] to disable send token to response header
        'cookie' => 'X-Auth-Token',  // Set [false/null/empty] to disable send token to response cookie
    ],

    'autoload_middleware' => true,  // Auto add to middleware HungDX\AuthToken\AuthTokenMiddleware to every request
];
