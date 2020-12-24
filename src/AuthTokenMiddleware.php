<?php

namespace HungDX\AuthToken;

use Closure;
use Illuminate\Http\RedirectResponse;
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

        $userToken = $guard->getUserToken();
        if ($userToken->isTokenChanged()) {
            $response = $guard->sendToken($response);
            $userToken->save();
        }

        return $response;
    }
}
