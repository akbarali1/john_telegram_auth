<?php
declare(strict_types=1);

namespace Auth\Factory;

use Auth\Models\AccessToken;
use Carbon\Carbon;
use Johncms\System\Http\Environment;
use Johncms\System\Http\Request;
use Johncms\Users\User;
use Johncms\Users\UserFactory;
use Psr\Container\ContainerInterface;

class UserAuthFactory extends UserFactory
{
	public const CookieId    = 'cutid';
	public const CookieToken = 'cutn';
	
	/** @var Environment */
	private $env;
	
	/** @var Request */
	private $request;
	
	public function __invoke(ContainerInterface $container): User
	{
		$this->env     = $container->get(Environment::class);
		$this->request = $container->get(Request::class);
		
		return $this->getUserData();
	}
	
	/**
	 * @return User
	 */
	protected function getUserData(): User
	{
		$userToken = $this->request->getCookie(static::CookieToken, '', FILTER_SANITIZE_STRING);
		$userId    = (int) $this->request->getCookie(static::CookieId, 0, FILTER_SANITIZE_NUMBER_INT);
		//		print_r($_COOKIE);
		//		die('asas');
		//		echo $userId."<br>";
		//		echo $userToken."<br>";
		if ($userId && $userToken) {
			return $this->authentication($userId, $userToken);
		}
		
		return new User();
	}
	
	private function authentication(int $userId, string $token): ?User
	{
		$user = (new User())->find($userId);
		if ($user) {
			$accessToken = (new AccessToken())
				->where('token', '=', $token)
				->where('user_id', '=', $userId)
				->select(['expires_at', 'last_used_at', 'id'])
				->latest()
				->first();
			if ($accessToken && $this->checkPermit($user) && Carbon::parse($accessToken->expires_at)->gt(date('Y-m-d H:i:s'))) {
				$this->ipHistory($user);
				$accessToken->update(['last_used_at' => date('Y-m-d H:i:s')]);
				
				return $user;
			}
			// Если авторизация не прошла
			++$user->failed_login;
			$user->save();
		}
		$this->userUnset();
		
		return new User();
	}
	
	private function checkPermit(User $user): bool
	{
		return $user->failed_login < 3
			|| ($user->failed_login > 2
				&& $user->ip === $this->env->getIp(false)
				&& $user->browser === $this->env->getUserAgent());
	}
	
	/**
	 * Фиксация истории IP адресов пользователя
	 *
	 * @param  User  $user
	 * @return void
	 */
	protected function ipHistory(User $user): void
	{
		$ip_via_proxy = $this->env->getIpViaProxy(false);
		$ip_via_proxy = empty($ip_via_proxy) ? '' : $ip_via_proxy;
		
		if ($user->ip_via_proxy !== $ip_via_proxy || $user->ip !== $this->env->getIp(false)) {
			// Удаляем из истории текущий адрес (если есть)
			$ip_history = $user->ipHistory();
			$ip_history->where('ip', '=', $this->env->getIp())
				->where('ip_via_proxy', '=', $this->env->getIpViaProxy())
				->delete();
			
			// Вставляем в историю предыдущий адрес IP
			$ip_history->create(
				[
					'user_id'      => $user->id,
					'ip'           => ip2long($user->ip),
					'ip_via_proxy' => ip2long($user->ip_via_proxy),
					'time'         => $user->lastdate,
				]
			);
			
			// Обновляем текущий адрес в таблице `users`
			$user->ip           = $this->env->getIp(false);
			$user->ip_via_proxy = empty($ip_via_proxy) ? 0 : $ip_via_proxy;
			$user->save();
		}
	}
	
	/**
	 * Уничтожаем данные авторизации юзера
	 *
	 * @return void
	 */
	protected function userUnset(): void
	{
		setcookie(static::CookieToken, '');
		setcookie(static::CookieId, '');
	}
	
}
