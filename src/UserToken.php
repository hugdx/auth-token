<?php


namespace HungDX\AuthToken;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Log;

/**
 * Class UserTokens
 * @package App\Models
 * @property int $id
 * @property string $auth_identifier
 * @property string $token
 * @property boolean $remember
 * @property string|Carbon $created_at
 * @property string|Carbon $updated_at
 */
class UserToken extends Model
{
    protected $primaryKey = 'id';

    protected $table = 'user_tokens';

    protected $casts = [
        'remember' => 'boolean',
    ];

    protected $lifetime = [
        'refresh' => 0,
        'expired' => 0,
    ];

    public function isExpired(): bool
    {
        if ($this->remember) {
            return false;
        }

        $diffInSeconds = Carbon::now()->diffInSeconds($this->updated_at);
        return $diffInSeconds > ($this->lifetime['expired'] ?? 0);
    }

    public function isNeedRefreshToken(): bool
    {
        $diffInSeconds = Carbon::now()->diffInSeconds($this->updated_at);
        return $diffInSeconds > ($this->lifetime['refresh'] ?? 0);
    }

    public function generateToken(): void
    {
        $this->token = md5($this->auth_identifier . '#' . time() . '#' . uniqid() . '#' . config('app.key'));
    }

    public function isTokenChanged(): bool
    {
        return $this->token !== $this->getOriginal('token');
    }

    public function getToken(): ?string
    {
        if (!$this->auth_identifier || !$this->token) {
            return null;
        }

        return Crypt::encrypt([
            'auth_identifier' => $this->auth_identifier,
            'token'           => $this->token,
        ]);
    }

    public function setLifeTime(array $lifetime)
    {
        if (isset($lifetime['expired']) && $lifetime['expired'] >= 0) {
            $this->lifetime['expired'] = intval($lifetime['expired']);
        }

        if (isset($lifetime['refresh']) && $lifetime['refresh'] >= 0) {
            $this->lifetime['refresh'] = intval($lifetime['refresh']);
        }
    }

    public static function retrieveByToken(string $token): ?UserToken
    {
        if (!$token) {
            return null;
        }

        try {
            $payload = Crypt::decrypt($token);
            if (!$payload || !is_array($payload)) {
                return null;
            }

            return UserToken::query()
                ->where('auth_identifier', $payload['auth_identifier'])
                ->where('token', $payload['token'])
                ->first();
        } catch (\Exception $e) {
            Log::alert(__METHOD__ . '#' . __LINE__ . " Unable decrypt payload");
            return null;
        }
    }

    /** Remove tokens unused
     *
     * @param int|null $expiredAfterSeconds
     */
    public static function deleteTokensExpired(?int $expiredAfterSeconds)
    {
        $REMEMBER_FLAG_ON = 1;
        static::query()
            ->where('remember', '!=', $REMEMBER_FLAG_ON)
            ->whereDate('updated_at', '<', Carbon::now()->subSeconds($expiredAfterSeconds))
            ->delete();
    }

    /**
     * Remove tokens by auth identifier (user_id/email...)
     *
     * @param $authIdentifier
     */
    public static function deleteTokensById($authIdentifier)
    {
        static::query()
            ->where('auth_identifier', '=', $authIdentifier)
            ->delete();
    }
}
