<?php
declare(strict_types=1);

namespace Auth\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * @mixin Builder
 *
 * @property int     $id          - Идентификатор
 * @property int     $user_id     - Идентификатор
 * @property int     $telegram_id - Идентификатор
 * @property ?string $name
 * @property ?string $token
 * @property ?string $ip_address
 * @property ?string $user_agent
 * @property ?string $last_used_at
 * @property ?string $expires_at
 */
class AccessToken extends Model
{
	protected $table    = 'access_tokens';
	protected $fillable = [
		'user_id',
		'telegram_id',
		'name',
		'token',
		'user_agent',
		'ip_address',
		'last_used_at',
		'expires_at',
	];
	
}
