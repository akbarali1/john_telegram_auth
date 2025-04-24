<?php
declare(strict_types=1);

namespace Auth\Factory;

use Auth\Models\AccessToken;
use Johncms\System\Http\Environment;
use Johncms\System\Http\Request;
use Johncms\Users\User;
use Psr\Container\ContainerInterface;

class UserAuthFactory
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
		$userPassword = md5($this->request->getCookie('cups', '', FILTER_SANITIZE_STRING));
		$userId       = (int) $this->request->getCookie('cuid', 0, FILTER_SANITIZE_NUMBER_INT);
		
		if ($userId && $userPassword) {
			return $this->authentication($userId, $userPassword);
		}
		
		$userToken = $this->request->getCookie(static::CookieToken, '', FILTER_SANITIZE_STRING);
		$userId    = (int) $this->request->getCookie(static::CookieId, 0, FILTER_SANITIZE_NUMBER_INT);
		if ($userId && $userToken) {
			return $this->authenticationTelegram($userId, $userToken);
		}
		
		return new User();
	}
	
	private function authentication(int $userId, string $userPassword): ?User
	{
		$user = (new User())->find($userId);
		
		if ($user) {
			if ($userPassword === $user->password && $this->checkPermit($user)) {
				$this->ipHistory($user); // Фиксируем историю IP
				
				return $user;
			}
			// Если авторизация не прошла
			++$user->failed_login;
			$user->save();
		}
		$this->userUnset();
		
		return new User();
	}
	
	private function authenticationTelegram(int $userId, string $token): ?User
	{
		$user = (new User())->find($userId);
		if ($user) {
			$explode     = explode('|', $token);
			$tokenId     = (int) ($explode[0] ?? 0);
			$accessToken = (new AccessToken())
				->where('id', '=', $tokenId)
				->where('user_id', '=', $userId)
				->where('expires_at', '>', date('Y-m-d H:i:s'))
				->where('token', '=', $explode[1] ?? '')
				->where('name', '=', 'Telegram')
				->select(['expires_at', 'last_used_at', 'id'])
				->find($tokenId);
			if ($accessToken && $this->checkPermit($user)) {
				$path = $this->request->getUri()->getPath();
				if ($path === '/login' || $path === '/register') {
					$this->userUnsetTelegram();
					
					return new User();
				}
				
				$this->ipHistory($user);
				$accessToken->update(['last_used_at' => date('Y-m-d H:i:s')]);
				
				return $user;
			}
			// Если авторизация не прошла
			++$user->failed_login;
			$user->save();
		}
		$this->userUnsetTelegram();
		
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
		setcookie('cuid', '');
		setcookie('cups', '');
	}
	
	/**
	 * Уничтожаем данные авторизации юзера через телеграм
	 *
	 * @return void
	 */
	protected function userUnsetTelegram(): void
	{
		setcookie(static::CookieToken, '');
		setcookie(static::CookieId, '');
	}
	
}
