<?php

namespace App\Services\Auth;

use Adldap\AdldapInterface;
use Adldap\Models\User as AdldapUser;
use App\Models\Role;
use App\Models\User;
use Error;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class LdapAuth
{

  const USER_CONNECTION = "user-conn";
  protected $adldap;

  public function __construct()
  {
    $this->adldap = $this->getAdldap();
  }


  /**
   * Попытаться аутентифицировать пользовтеля через LDAP при успехе вызываем Auth::login().
   *
   * @param  array  $credentials
   *
   * @return bool|string
   */
  public function attempt($guard, array $credentials)
  {
    $this->validateCredentials($credentials);

    ["email" => $email, "password" => $password] = $credentials;

    $user = $this->login($email, $password);

    if (!$user) return false;

    return $guard->login($user);
  }

  /*
       Если суффикс пользователя соответствует суффиксу AD/не является email и в настройках включена LDAP-авторизация
           Подключаемся к LDAP-серверу, если сервер не доступен - отказываем в авторизации
               Ищем пользователя в LDAP, если пользователь не найден - отказываем в авторизации
                   Проверяем корректность пароля, если пароль некорректный - отказываем в авторизации
                       Подбираем роль для пользователя, если подходящей роли нет - отказываем в авторизации
                           Проверяем, есть ли пользователь в БД.
                               Пользователь существует в БД.
                                   Если роль не совпадает - меняем роль.
                                   Авторизуемся под найденным пользователем
                               Пользователь не существует в БД
                                   Создаем пользователя
                                   Авторизуемся под созданным пользователем
   */
  public function login($email, $password)
  {
    [$username, $suffix] = $this->destructEmail($email);

    $entries = $this->findUser($username);

    if ($entries->count() == 0)
      return $this->logError("Пользовтель не найден в домене", ["username" => $username]);

    if ($entries->count() > 1)
      return $this->logError("Найдено слишком много записей в домене", ["username" => $username]);

    $user = $entries->first();

    if (!$this->tryAuthUser($user, $password)) {
      return $this->logError("Не удалось авторизироваться по найденому DN", ["ldap_user_dn" => $user->distinguishedname, "username" => $username]);
    }

    $roles = Role::getCompatibleWithLdap();

    if ($roles->count() == 0) {
      return $this->logError("В системе не заведено ни одной роли, которая могла бы соответствовать ролям AD пользователей");
    }

    if (!($roleCompatibleWithLdap = $this->findUserRole($user, $roles))) {
      return $this->logError("У пользователя нет совместимиых ролей", [$user]);
    }

    return User::syncWithLdap($user, $roleCompatibleWithLdap, "{$username}{$suffix}");
  }

  /**
   * Авторизируем пользователя
   */
  public function tryAuthUser(AdldapUser $user, $password): bool
  {
    try {
      $config = $this->adldap->getDefaultProvider()->getConfiguration();
      $user_dn = implode(",", $user->distinguishedname);

      $config->set("username", $user_dn);
      $config->set("password", $password);

      $this->adldap->addProvider($config, static::USER_CONNECTION);
      $this->adldap->connect(static::USER_CONNECTION);

      return true;
    } catch (\Throwable $th) {
      return false;
    }
  }

  public function findUser(string $username): Collection
  {
    return  $this->adldap->connect()
      ->search()
      ->rawFilter("(&(objectClass=user)(objectCategory=person)(sAMAccountName='{$username}'))")
      ->get();
  }

  public function findUserRole(AdldapUser $user, Collection $roles): ?Role
  {
    $groups = collect($user->getGroupNames());
    $matching_role = null;

    foreach ($roles as $role) {
      if ($groups->contains($role->ad_role)) {
        $matching_role = $role;
        break;
      }
    }

    return $matching_role;
  }

  public function destructEmail($email)
  {
    $suffix = $this->getSuffix();
    $ldap_suffix_pattern = '/' . preg_quote($suffix) . '$/';
    $username = preg_replace($ldap_suffix_pattern, '', $email);
    return [$username, $suffix];
  }

  public function getAdldap(): ?AdldapInterface
  {
    return resolve(AdldapInterface::class);
  }

  public function getConfig()
  {
    return $this->getAdldap()->getDefaultProvider()->getConfiguration();
  }

  public function getSuffix(): string
  {
    return $this->getConfig()->get("account_suffix");
  }

  public function isEnabledLdap(): bool
  {
    return (bool) config("ldap.enabled");
  }

  public function isLdapEmail(string $email): bool
  {
    $ldap_suffix = $this->getSuffix();

    $ldap_suffix_pattern = '/' . preg_quote($ldap_suffix) . '$/';

    return (bool) preg_match($ldap_suffix_pattern, $email);
  }

  public function validateCredentials(array $credentials)
  {
    $validator = Validator::make($credentials, [
      'email' => 'required|email|max:255',
      'password' => 'required|max:255',
    ]);

    if ($validator->fails()) {
      throw new Error(__("auth.errors.invalidLoginOrPassword") . " (AD)");
    }
  }

  /**
   *  Логгирует сообщение в формате: "LDAP AUTH ERROR: текст ошибки"
   *  и возвращает false для удобства
   */
  private static function logError(string $message, array $context = []): bool
  {
    Log::error("LDAP AUTH ERROR: " . $message, $context);
    return false;
  }
}
