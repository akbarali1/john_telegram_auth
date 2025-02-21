<?php
/**
 * This file is part of JohnCMS Content Management System.
 *
 * @copyright JohnCMS Community
 * @license   https://opensource.org/licenses/GPL-3.0 GPL-3.0
 * @link      https://johncms.com JohnCMS Project
 *
 * @author    Akbarali
 * Date: 20.02.2025
 * @telegram @kbarli
 * @website http://akbarali.uz
 * Email: Akbarali@uzhackersw.uz
 * Johncms Профил: https://johncms.com/profile/?user=38217
 */

namespace Auth\Install;

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;

class TelegramUsersInstall
{
	public static function install(): void
	{
		$schema = Capsule::Schema();
		if (!$schema->hasTable('telegram_users')) {
			$schema->create(
				'telegram_users',
				static function (Blueprint $table) {
					$table->increments('id');
					$table->integer('user_id');
					$table->bigInteger('telegram_id');
					$table->string('username', 255)->nullable();
					$table->string('first_name', 255)->nullable();
					$table->string('last_name', 255)->nullable();
					$table->string('photo_url', 255)->nullable();
					$table->string('language', 10)->nullable();
					$table->dateTime('created_at')->default(Capsule::raw('CURRENT_TIMESTAMP'));
					$table->dateTime('updated_at')->default(Capsule::raw('CURRENT_TIMESTAMP'));
				}
			);
		}
		
		if (!$schema->hasTable('access_tokens')) {
			$schema->create(
				'access_tokens',
				static function (Blueprint $table) {
					$table->bigInteger('id')->autoIncrement();
					$table->integer('user_id');
					$table->bigInteger('telegram_id');
					$table->string('name', 255);
					$table->string('token', 255);
					$table->string('user_agent', 255);
					$table->string('ip_address', 45);
					$table->dateTime('last_used_at');
					$table->dateTime('expires_at');
					$table->dateTime('created_at')->default(Capsule::raw('CURRENT_TIMESTAMP'));
					$table->dateTime('updated_at')->default(Capsule::raw('CURRENT_TIMESTAMP'));
				}
			);
		}
	}
	
}
