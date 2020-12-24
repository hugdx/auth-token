<?php


namespace HungDX\AuthToken;


use Carbon\Carbon;
use Exception;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Log;

class AuthTokenGuard implements StatefulGuard
{
    use GuardHelpers;

    /** @var array */
    private $config = [];

    /** @var UserToken|bool|null */
    private $userToken = null;

    /** @var Request */
    protected $request;

    /** @var bool */
    protected $loggedOut = true;

    /** @var null|Authenticatable */
    protected $lastAttempted = null;

    /** Create a new authentication guard. */
    public function __construct(UserProvider $provider, Request $request, $config)
    {
        $this->request  = $request;
        $this->provider = $provider;
        $this->config   = is_array($config) ? $config : [];

        $this->config['lifetime'] = [
            'expired' => $config['lifetime']['expired'] ?? config('auth-token.lifetime.expired'),
            'refresh' => $config['lifetime']['refresh'] ?? config('auth-token.lifetime.refresh'),
        ];

        $this->config['token_field'] = [
            'header' => $config['token_field']['header'] ?? config('auth-token.token_field.header'),
            'cookie' => $config['token_field']['cookie'] ?? config('auth-token.token_field.cookie'),
        ];
    }

    /** Get the currently authenticated user */
    public function user(): ?Authenticatable
    {
        return $this->user ?: null;
    }

    /** Set the current user. */
    public function setUser(AuthenticatableContract $user)
    {
        $this->user      = $user;
        $this->loggedOut = false;
        return $this;
    }

    /** Log a user into the application. */
    public function login(AuthenticatableContract $user, bool $remember = false)
    {
        $this->setUser($user);
        $this->userToken = $this->createUserToken($user, $remember);
    }

    /** Attempt to authenticate a user using the given credentials. */
    public function attempt(array $credentials = [], bool $remember = false): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);
            return true;
        }
        return false;
    }

    /** Log a user into the application without sessions or cookies. */
    public function once(array $credentials = []): bool
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }

        return false;
    }

    /** Log the given user ID into the application without sessions or cookies. */
    public function onceUsingId($id): ?Authenticatable
    {
        if (($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);
            return $user;
        }
        return null;
    }

    /** Log the given user ID into the application. */
    public function loginUsingId($id, $remember = false): ?Authenticatable
    {
        if (($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);
            return $user;
        }
        return null;
    }

    /** Determine if the user was authenticated via "remember me" cookie. */
    public function viaRemember(): bool
    {
        // Nothing need to do for this function. Just call $this->user() is enough
        return false;
    }

    /** Validate a user's credentials. */
    public function validate(array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);
        return $this->hasValidCredentials($user, $credentials);
    }

    /** Log the user out of the application. */
    public function logout(): void
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        $this->user = null;
        $this->userToken = null;
        $this->loggedOut = true;
    }

    /** Remove the user data from the session / cookies / database. */
    protected function clearUserDataFromStorage()
    {
        // Delete token from database
        if ($this->userToken && $this->userToken->exists) {
            $this->userToken->delete();
        }
    }

    /** Create an UserToken */
    protected function createUserToken(AuthenticatableContract $user, bool $remember = false): UserToken
    {
        $userToken = new UserToken();
        $userToken->auth_identifier = $user->getAuthIdentifier();
        $userToken->remember = $remember;
        $userToken->generateToken();
        $userToken->setLifeTime($this->config['lifetime']);
        return $userToken;
    }

    /** Get UserToken from client */
    private function getUserTokenFromRequest(): ?UserToken
    {
        // 1. Get token from Request
        $token = '';
        if ($this->config['token_field']['header']) {
            $token = $this->getRequest()->header($this->config['token_field']['header']);
        }
        if (!$token && $this->config['token_field']['cookie']) {
            $token = $this->getRequest()->cookie($this->config['token_field']['cookie']);
        }

        // 2. Retire UserToken from database
        $userToken = UserToken::retrieveByToken($token);
        if (!$userToken) {
            return null;
        }

        // 3. Check token expiring
        $userToken->setLifeTime($this->config['lifetime']);
        if ($userToken->isExpired()) {
            $userToken->delete();
            return null;
        }

        // 4. Renew token
        if ($userToken->isNeedRefreshToken()) {
            $userToken->generateToken();
        }

        return $userToken;
    }

    /** Get user from user token */
    public function getUserToken(): ?UserToken
    {
        if ($this->userToken === false) {
            return null;
        }

        if (is_null($this->userToken)) {
            $this->userToken = $this->getUserTokenFromRequest() ?: false;
        }

        return $this->userToken ?: null;
    }

    /** Determine if the user matches the credentials. */
    protected function hasValidCredentials($user, $credentials): bool
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /** Set the current request instance. */
    public function setRequest(Request $request): self
    {
        $this->request = $request;
        return $this;
    }

    /** Get the current request instance. */
    public function getRequest()
    {
        return $this->request ?: \Symfony\Component\HttpFoundation\Request::createFromGlobals();
    }

    /** Send token to client via: Header [OR / AND] Cookie */
    public function sendToken($response)
    {
        $token           = $this->getUserToken()->getToken() ?? '';
        $headerFieldName = $this->config['token_field']['header'];
        $cookieFieldName = $this->config['token_field']['cookie'];

        // Developer disabled send token to client
        if (!$headerFieldName && !$cookieFieldName) {
            return $response;
        }

        // When client DO NOT sent token to server [AND] server haven't got token -> Ignore that
        if (empty($token)) {
            $hasTokenInHeader = $headerFieldName && $this->getRequest()->hasHeader($headerFieldName);
            $hasTokenInCookie = $cookieFieldName && $this->getRequest()->hasCookie($cookieFieldName);
            if (!$hasTokenInHeader && !$hasTokenInCookie) {
                return $response;
            }
        }

        $response = $response instanceof RedirectResponse ? $response : response($response);

        // Send token via header
        if ($headerFieldName) {
            $response->header($headerFieldName, $token);
        }

        // Send token via cookie
        if ($cookieFieldName) {
            $cookie = cookie($cookieFieldName, $token, $this->config['lifetime']['expired'] / 60);
            $response->cookie($cookie);
        }

        return $response;
    }
}
