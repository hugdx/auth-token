## Laravel Auth-Token
Driver for Laravel Auth by using tokens 

####Required:
    "php": "^7.3|^8",
    "laravel/framework": "^7|^8"

## Installation

#### Require this package with composer

```shell
composer require hungdx/auth-token
```

#### Add the AuthTokenProvider to the providers array in config/app.php

```php
HungDX\AuthToken\AuthTokenProvider::class,
```

#### Create `user_tokens` talbe
```shell
php artisan migrate --path="vendor/hungdx/auth-token/migrations"
```

#### Copy the package config to your local config with the publish command:

```shell
php artisan vendor:publish --provider="HungDX\AuthToken\AuthTokenProvider"
```

### Lumen:

For Lumen, register a different Provider in `bootstrap/app.php`:

```php
$app->register(HungDX\AuthToken\AuthTokenProvider::class);
```

To change the configuration, copy the file to your config folder and enable it:

```php
$app->configure('auth-token');
```

## Usage

In the `bootstrap/auth.php`, at `guards` section,  change driver to `auth-token`. For example:

```php
    'guards' => [
        'web' => [
            'driver'   => 'auth-token',
            'provider' => 'users',
        ],

        'api' => [
            'driver'   => 'auth-token',
            'provider' => 'users',
        ],
    ],
```

## Configuration
#### File `config/auth-token.php`
```php
return [
    'lifetime' => [
        'expired' => 7 * 24 * 3600,  // Lifetime of token before expired. Default 7 days
        'refresh' => 3600,           // The minimum seconds before change the token. Default 1 hour
    ],

    'token_field' => [
        'header' => 'Authorization', // Set [false/null/empty] to disable send token to response header  
        'cookie' => 'X-Auth-Token',  // Set [false/null/empty] to disable send token to response cookie
    ],

    'autoload_middleware' => true,  // Auto add to middleware HungDX\AuthToken\AuthTokenMiddleware to every request
];
```
