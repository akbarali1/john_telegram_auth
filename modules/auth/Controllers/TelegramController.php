<?php

/**
 * Image Guestbook Controller Class
 *
 * @author Akbarali
 * Date: 31.12.2021
 * @telegram @kbarli
 * @website http://akbarali.uz
 * Email: Akbarali@uzhackersw.uz
 * Johncms Профил: https://johncms.com/profile/?user=38217
 * На тему: https://johncms.com/forum/?type=topic&id=12200
 */

declare(strict_types=1);

namespace Auth\Controllers;

use Auth\Factory\UserAuthFactory;
use Auth\Models\AccessToken;
use Auth\Models\TelegramUsers;
use Carbon\Carbon;
use Exception;
use Johncms\Controller\BaseController;
use Johncms\System\Http\Request;

class TelegramController extends BaseController
{
	protected $botToken;
	protected $secretKey;
	protected $expires;
	
	/** @var string */
	public const VERSION = 'Akbarali Telegram Login 0.1';
	
	public function __construct()
	{
		parent::__construct();
		$this->botToken = di('config')['botToken'];
		$this->expires  = di('config')['expiresToken'];
	}
	
	/**
	 * @throws Exception
	 */
	public function index(Request $requests): void
	{
		$request = json_decode($requests->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
		if ($this->checkTelegramAuthorization($request)) {
			$tgUser = (new TelegramUsers())->where('telegram_id', '=', $request['id'])->first();
			if (!$tgUser) {
				$this->response([
					'success' => false,
					'error'   => 'Unauthorized 404',
				]);
			}
			$loginUser = (new \Johncms\Users\User())->find($tgUser->user_id);
			
			if ($loginUser->failed_login >= 3) {
				$this->response([
					'success' => false,
					'error'   => 'You can only access via a default login.',
				]);
			}
			
			$loginUser->update([
				'failed_login' => 0,
				'sestime'      => time(),
			]);
			
			$token = hash_hmac('sha512', uniqid((string) mt_rand(), true), $this->botToken);
			setcookie(UserAuthFactory::CookieId, (string) $loginUser->id, time() + $this->expires * 24 * 3600, '/');
			setcookie(UserAuthFactory::CookieToken, $token, time() + $this->expires * 24 * 3600, '/');
			AccessToken::query()
				->where('user_id', '=', $loginUser->id)
				->where('telegram_id', '=', $tgUser->telegram_id)
				->update([
					"expires_at" => Carbon::now()->toDateTimeString(),
				]);
			
			AccessToken::query()->create([
				'user_id'      => $loginUser->id,
				'telegram_id'  => $tgUser->telegram_id,
				'name'         => 'Telegram',
				'token'        => $token,
				"user_agent"   => $_SERVER['HTTP_USER_AGENT'],
				'ip_address'   => $_SERVER['REMOTE_ADDR'],
				'last_used_at' => date('Y-m-d H:i:s'),
				"expires_at"   => Carbon::now()->addDays($this->expires)->toDateTimeString(),
			]);
			
			$this->response([
				'success' => true,
			]);
		}
		
		$this->response([
			'success' => false,
			'error'   => 'Unauthorized',
		]);
	}
	
	private function response(array $data)
	{
		header('Content-Type: application/json');
		die(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
	}
	
	/**
	 * @throws Exception
	 */
	public function checkTelegramAuthorization(array $authData): bool
	{
		$check_hash = $authData['hash'];
		unset($authData['hash']);
		$data_check_arr = [];
		foreach ($authData as $key => $value) {
			$data_check_arr[] = $key.'='.$value;
		}
		sort($data_check_arr);
		$data_check_string = implode("\n", $data_check_arr);
		$secret_key        = hash('sha256', $this->botToken, true);
		$hash              = hash_hmac('sha256', $data_check_string, $secret_key);
		if (strcmp($hash, $check_hash) !== 0) {
			return false;
			//throw new Exception('Data is NOT from Telegram');
		}
		if ((time() - $authData['auth_date']) > 86400) {
			return false;
			//throw new Exception('Data is outdated');
		}
		
		return true;
	}
	
}
