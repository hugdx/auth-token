## Laravel Auth-Token
Driver for Laravel Auth by using tokens

### The story
We need a way to authenticate for *web* and *api*. Laravel supports drivers **session** *(SessionGuard)*, **token** *(TokenGuard)*, **request** *(RequestGuard)* but it is not strong enough.
 - **SessionGuard**: Unable use for api. On the Web, with the same user and remember is on -> only one device can use this feature.
 - **TokenGuard**: It is not designed for Web and not supported multiple device login at sametime 
 - **RequestGuard**: Not checked yet

> For *api*, we have got **JWT**, why not use that?
>> **JWT** very easy to create and verify tokens, but it is not strong enough to manage the tokens. When you want to remove a token which was created before, no way to do that until the token expires.      


### What do the features of this driver?
 - Supported for *web*, *api* or any other purposes.
 - Support multiple devices login for a user at sametime.
 - With a good config, we can count number users/devices of user are logged-in (Set refresh lifetime to small enough and count records in the table *user_tokens*)
 - All tokens stored in the database. To logout a device, just delete the token record of this device. 

#### Required:
    "php": "^7.1.3|^8",
    "laravel/framework": "^5.8|^6|^7|^8"

  
  
## Installation

#### Require this package with composer

```shell
composer require hungdx/auth-token
```

### Laravel
Add the AuthTokenProvider to the providers array in `config/app.php`

```php
HungDX\AuthToken\AuthTokenProvider::class,
```

Create `user_tokens` table
```shell
php artisan migrate --path="vendor/hungdx/auth-token/migrations"
```

### Lumen

For Lumen, register a different Provider in `bootstrap/app.php`:

```php
$app->register(HungDX\AuthToken\AuthTokenProvider::class);
```

To change the configuration, copy the file to your config folder and enable it:

```php
$app->configure('auth-token');
```

#### Create `user_tokens` table
```shell
php artisan migrate --path="vendor/hungdx/auth-token/migrations"
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

If you want to customize the config, run command:

```shell
php artisan vendor:publish --provider="HungDX\AuthToken\AuthTokenProvider"
```

File `config/auth-token.php`
```php
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
```
  
  
## Changes
#### 1.0.2 (2020-12-30)
 * Support PHP 7.1.3, Laravel 5.8

#### 1.0.1 (2020-12-25)
 * Support remember flag. When remember is on, The token never expire until logged out
 * Support PHP 7.2
 * Fix phpcs
 * Fix migration

#### 1.0.0 (2020-12-24)
 * Add auth-token driver for Auth of laravel/lumen
 * Auto add middleware to all router groups
