<?php // auth.php
if (session_status() === PHP_SESSION_NONE) {
  // Mantém a sessão viva "para sempre" (janela deslizante de ~5 anos)
  $sessionLifetime = 60 * 60 * 24 * 365 * 5;
  ini_set('session.gc_maxlifetime', (string)$sessionLifetime);
  ini_set('session.cookie_lifetime', (string)$sessionLifetime);

  // Configurações do cookie da sessão (centralizadas aqui)
  $secure = !empty($_SERVER['HTTPS']);
  session_set_cookie_params([
    'lifetime' => $sessionLifetime,
    'path'     => '/',
    'domain'   => ini_get('session.cookie_domain') ?: '',
    'secure'   => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
  ]);

  ini_set('session.cookie_httponly', '1');
  ini_set('session.cookie_samesite', 'Lax'); // se for SSO/embeds, ajuste
  if (!empty($_SERVER['HTTPS'])) ini_set('session.cookie_secure', '1');
  session_start();

    // Renova o cookie da sessão a cada requisição para manter a janela sempre ativa
  $params = session_get_cookie_params();
  setcookie(session_name(), session_id(), [
    'expires'  => time() + $sessionLifetime,
    'path'     => $params['path'] ?? '/',
    'domain'   => $params['domain'] ?? '',
    'secure'   => $params['secure'] ?? !empty($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => $params['samesite'] ?? 'Lax',
  ]);
}

require_once __DIR__ . '/db.php'; // sua função pdo()

/**
 * Carrega os slugs de papéis (roles) do usuário e injeta em $_SESSION['user']['roles'].
 * Opcional: o resto do sistema já busca do BD, mas ter aqui ajuda a consistência.
 */
function _auth_load_user_roles_into_session(int $userId): void {
  try {
    $stmt = pdo()->prepare("
      SELECT r.slug
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = :uid
    ");
    $stmt->execute([':uid' => $userId]);
    $roles = $stmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
    // normaliza leve (lowercase/trim); o index.php já normaliza/acerta acentos
    $roles = array_values(array_unique(array_map(function($s){
      $s = strtolower(trim((string)$s));
      return $s;
    }, $roles)));
    if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) $_SESSION['user'] = [];
    $_SESSION['user']['roles'] = $roles;
  } catch (Throwable $e) {
    // silencioso
  }
}

function auth_login(string $email, string $password): bool {
  $stmt = pdo()->prepare("SELECT * FROM users WHERE email = :e AND is_active=1");
  $stmt->execute([':e'=>$email]);
  $u = $stmt->fetch(PDO::FETCH_ASSOC);
  if (!$u) return false;
  if (!password_verify($password, $u['pass_hash'])) return false;

  // sucesso
  session_regenerate_id(true);

  // Chaves "legadas"
  $_SESSION['uid']    = (int)$u['id'];
  $_SESSION['uname']  = $u['name'];
  $_SESSION['uemail'] = $u['email'];

  // Chave "canônica" esperada pelo resto do app
  $_SESSION['user'] = [
    'id'    => (int)$u['id'],
    'name'  => $u['name'] ?: $u['email'],
    'email' => $u['email'],
  ];

  // Opcional: já carrega roles em sessão (index.php ainda vai reconferir do BD)
  _auth_load_user_roles_into_session((int)$u['id']);

  return true;
}

function auth_logout(): void {
  // Logout desabilitado para manter as sessoes ativas e evitar limpezas involuntarias
  return;
}

/**
 * Usuário autenticado como array canônico (id, name, email).
 * Mantém compat com o que o index.php espera.
 */
function auth_user() {
  if (isset($_SESSION['user']) && is_array($_SESSION['user']) && !empty($_SESSION['user']['id'])) {
    return [
      'id'    => (int)$_SESSION['user']['id'],
      'name'  => $_SESSION['user']['name']  ?? ($_SESSION['uname']  ?? ''),
      'email' => $_SESSION['user']['email'] ?? ($_SESSION['uemail'] ?? ''),
    ];
  }
  if (isset($_SESSION['uid'])) {
    return [
      'id'    => (int)$_SESSION['uid'],
      'name'  => $_SESSION['uname']  ?? ($_SESSION['user']['name']  ?? ''),
      'email' => $_SESSION['uemail'] ?? ($_SESSION['user']['email'] ?? ''),
    ];
  }
  return null;
}

/**
 * Aliases p/ compat com o formulário e outras páginas.
 * O index.php tenta auth_current_user()/current_user()/get_authenticated_user().
 */
if (!function_exists('auth_current_user')) {
  function auth_current_user() { return auth_user(); }
}
if (!function_exists('current_user')) {
  function current_user() { return auth_user(); }
}
if (!function_exists('get_authenticated_user')) {
  function get_authenticated_user() { return auth_user(); }
}

function require_auth(): void {
  if (!auth_user()) {
    header('Location: /login.php?next='.urlencode($_SERVER['REQUEST_URI']));
    exit;
  }
}

// --- autorização --- //
function user_can(string $action, string $resource_slug, ?string $unidade=null): bool {
  $u = auth_user();
  if (!$u) return false;
  $uid = (int)$u['id'];

  // admin short-circuit (se existir)
  $sqlAdmin = "SELECT 1
                 FROM user_roles ur
                 JOIN roles r ON r.id=ur.role_id
                WHERE ur.user_id=:uid AND r.slug='admin' LIMIT 1";
  $adm = pdo()->prepare($sqlAdmin); $adm->execute([':uid'=>$uid]);
  if ($adm->fetch()) return true;

  $params = [':uid'=>$uid, ':action'=>$action, ':slug'=>$resource_slug];
  $extraJoin = ''; $extraWhere = '';
  if ($unidade !== null && $unidade !== '') {
    $extraJoin = " LEFT JOIN role_units ru ON ru.role_id = r.id ";
    $extraWhere= " AND (ru.unidade = :un OR NOT EXISTS(SELECT 1 FROM role_units ru2 WHERE ru2.role_id=r.id)) ";
    $params[':un'] = $unidade;
  }

  $sql = "
    SELECT 1
      FROM user_roles ur
      JOIN roles r ON r.id=ur.role_id
      $extraJoin
      JOIN role_resource_permissions rrp ON rrp.role_id = r.id
      JOIN resources res ON res.id = rrp.resource_id
      JOIN permissions p ON p.id = rrp.permission_id
     WHERE ur.user_id = :uid
       AND p.action = :action
       AND res.slug = :slug
       $extraWhere
     LIMIT 1
  ";
  $st = pdo()->prepare($sql); $st->execute($params);
  return (bool)$st->fetch();
}

// Helpers de CSRF (mantém os nomes usados no projeto)
function csrf_token(): string {
  if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
  return $_SESSION['csrf'];
}
function csrf_check($token): bool {
  return isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], (string)$token);
}
