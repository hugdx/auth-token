<?php


namespace HungDX\AuthToken;


use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class AuthTokenProvider extends ServiceProvider
{
    public function register()
    {
        Auth::extend('auth-token', function ($app, $name, array $config) {
            $guard = new AuthTokenGuard(
                Auth::createUserProvider($config['provider'] ?? null),
                $app['request'],
                $config
            );
            $app->refresh('request', $guard, 'setRequest');
            return $guard;
        });

        $this->mergeConfigFrom(
            __DIR__ . '/../config/auth-token.php', 'auth-token'
        );
    }

    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/auth-token.php' => config_path('auth-token.php'),
        ]);

        $this->loadMigrationsFrom(__DIR__ . '/../migrations');

        // Add middleware
        if (config('auth-token.autoload_middleware')) {
            /** @var \Illuminate\Routing\Router $router */
            $router = $this->app['router'];

            $middlewareGroups = $router->getMiddlewareGroups();
            foreach ($middlewareGroups as $middlewareGroupName => $middlewareGroup) {
                if (!in_array(AuthTokenMiddleware::class, $middlewareGroup)) {
                    $router->pushMiddlewareToGroup($middlewareGroupName, AuthTokenMiddleware::class);
                }
            }
        }
    }
}
