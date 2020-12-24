<?php

namespace HungDX\AuthToken;

use Closure;
use Illuminate\Support\Facades\Auth;

class AuthTokenMiddleware
{
    /**
     * Auto send token to client
     *
     * @param $request
     * @param Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $guard = Auth::guard();
        if (function_exists('getAuthenticateGuard')) {
            $guard = getAuthenticateGuard();
        }

        if (!$guard || !$guard instanceof AuthTokenGuard) {
            return $next($request);
        }

        $response = $next($request);

        $response = $guard->sendToken($response);

        return $response;
    }
}
