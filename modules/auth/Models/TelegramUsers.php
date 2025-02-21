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
 * @property ?string $username
 * @property ?string $first_name
 * @property ?string $last_name
 * @property ?string $photo_url
 * @property ?string $language
 *
 * @method static Model|static query()
 */
class TelegramUsers extends Model
{
	protected $table    = 'telegram_users';
	protected $fillable = [
		'user_id',
		'telegram_id',
		'username',
		'first_name',
		'last_name',
		'photo_url',
		'language',
	];
	
}
