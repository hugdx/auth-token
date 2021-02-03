<?php


namespace HungDX\AuthToken;

use Exception;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Auth\Events\Login;

class AuthTokenGuard implements StatefulGuard
{
    use GuardHelpers;

    /** @var string */
    protected $name;

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

    /** @var Dispatcher */
    protected $events;

    /**
     * Create a new authentication guard.
     *
     * @param string $name
     * @param array $config
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     */
    public function __construct(
        string $name,
        array $config,
        UserProvider $provider
    ) {
        $this->name     = $name;
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

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     * @throws Exception
     */
    public function user()
    {
        $this->getUserToken();

        if (!$this->user) {
            return null;
        }

        $session_id = $this->getRequest()->hasSession() ? $this->getRequest()->session()->getId() : '';
        if ($this->userToken->session_id !== $session_id) {
            $this->userToken->session_id = $session_id;
            $this->fireAuthenticatedEvent($this->user);
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user      = $user;
        $this->loggedOut = false;
        $this->fireAuthenticatedEvent($user);
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    public function login(Authenticatable $user, $remember = false)
    {
        $this->userToken = $this->createUserToken($user, $remember);
        $this->fireLoginEvent($user, $remember);
        $this->setUser($user);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool  $remember
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);
            return true;
        }
        $this->fireFailedEvent($user, $credentials);
        return false;
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function once(array $credentials = [])
    {
        $this->fireAttemptEvent($credentials);

        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param  mixed  $id
     * @return \Illuminate\Contracts\Auth\Authenticatable|bool
     */
    public function onceUsingId($id)
    {
        if (($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);
            return $user;
        }
        return null;
    }

    /**
     * Log the given user ID into the application.
     *
     * @param  mixed  $id
     * @param  bool  $remember
     * @return \Illuminate\Contracts\Auth\Authenticatable|bool
     */
    public function loginUsingId($id, $remember = false)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);
            return $user;
        }

        return false;
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     *
     * @return bool
     */
    public function viaRemember()
    {
        // Nothing need to do for this function. Just call $this->user() is enough
        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     * @throws Exception
     */
    public function logout()
    {
        $this->clearUserDataFromStorage();
        $this->userToken = null;

        if (isset($this->events)) {
            $this->events->dispatch(new Logout($this->name, $this->user));
        }

        $this->user      = null;
        $this->loggedOut = true;
    }

    /**
     * Remove the user data from the session / cookies / database
     *
     * @throws Exception
     */
    protected function clearUserDataFromStorage()
    {
        // Delete token from database
        if ($this->userToken && $this->userToken->exists) {
            $this->userToken->delete();
        }

        // Remove form session
        if ($this->session) {
            $this->session->remove($this->getName());
        }
    }

    /**
     * Create an UserToken
     *
     * @param Authenticatable $user
     * @param bool $remember
     * @return UserToken
     */
    protected function createUserToken(Authenticatable $user, bool $remember = false): UserToken
    {
        $userToken                  = new UserToken();
        $userToken->auth_identifier = $user->getAuthIdentifier();
        $userToken->remember        = $remember;
        $userToken->session_id      = $this->request && $this->request->hasSession() ? $this->request->session()->getId() : '';
        $userToken->generateToken();
        $userToken->setLifeTime($this->config['lifetime']);
        return $userToken;
    }

    /**
     * Get UserToken from client
     *
     * @return UserToken|null
     * @throws Exception
     */
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
        $userToken = UserToken::retrieveByToken($token ?: '');
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

    /**
     * Get user from user token
     *
     * @return UserToken|null
     * @throws Exception
     */
    public function getUserToken(): ?UserToken
    {
        if ($this->userToken === false) {
            return null;
        }

        if (is_null($this->userToken)) {
            $this->userToken = $this->getUserTokenFromRequest() ?: false;
            if ($this->userToken) {
                $this->user = $this->provider->retrieveById($this->userToken->auth_identifier);
            }
        }

        return $this->userToken ?: null;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param $user
     * @param $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials): bool
    {
        $validated = !is_null($user) && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->fireValidatedEvent($user);
        }

        return $validated;
    }

    /**
     * Set the current request instance.
     *
     * @param Request $request
     * @return AuthTokenGuard
     */
    public function setRequest(Request $request): self
    {
        $this->request = $request;
        return $this;
    }

    /**
     * Get the current request instance
     *
     * @return Request|\Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        return $this->request ?: \Symfony\Component\HttpFoundation\Request::createFromGlobals();
    }

    /**
     * Send token to client via: Header [OR / AND] Cookie
     *
     * @param $response
     * @return mixed
     * @throws Exception
     */
    public function sendToken($response)
    {
        // Header already sent. Noway add more header
        if (headers_sent()) {
            return $response;
        }

        $token = '';
        if ($this->getUserToken()) {
            $token = $this->userToken->getToken() ?: '';
        }

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

        // Make sure $response is instance of Response
        if (!$response instanceof Response) {
            $response = response($response);
        }

        // Send token via header
        if ($headerFieldName) {
            $response->header($headerFieldName, $token);
        }

        // Send token via cookie
        if ($cookieFieldName) {
            switch (true) {
                // Delete cookie
                case empty($token):
                    $cookie = cookie()->forget($cookieFieldName, $token);
                    break;

                // Remember cookie forever when remember flag is on
                case $this->userToken->remember:
                    $cookie = cookie()->forever($cookieFieldName, $token);
                    break;

                // Normal cookie: just set to equal session
                default:
                    $cookie = cookie()->make($cookieFieldName, $token);
                    break;
            }
            $response->cookie($cookie);
        }

        // Save UserToken to database: Only save token when header added to response object
        if ($this->userToken && $this->userToken->isTokenChanged()) {
            $this->userToken->save();
        }

        return $response;
    }

    /**
     * Set the event dispatcher instance.
     *
     * @param Dispatcher|null $events
     * @return void
     */
    public function setDispatcher(?Dispatcher $events)
    {
        $this->events = $events;
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @param  bool  $remember
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Attempting($this->name, $credentials, $remember));
        }
    }

    /**
     * Fires the validated event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireValidatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Validated($this->name, $user));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
     * @return void
     */
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Login($this->name, $user, $remember));
        }
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireAuthenticatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Authenticated($this->name, $user));
        }
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array  $credentials
     * @return void
     */
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Failed($this->name, $user, $credentials));
        }
    }
}
