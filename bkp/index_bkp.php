<?php
require_once __DIR__ . '/auth.php';
require_auth(); // força login
require_once __DIR__ . '/db.php';
require_once __DIR__.'/navbar.php'; // carrega wrappers e a função de render
require_once __DIR__.'/ui/datepicker.php';

// --- Evita cache do HTML para não reaproveitar POST no refresh/back ---
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
header('Referrer-Policy: strict-origin-when-cross-origin');

// --- Sessão garantida ---
if (session_status() !== PHP_SESSION_ACTIVE) {
  session_start();
}

/** =========================================================
 *  [NOVO] Wrapper seguro para user_can() (igual do dashboard)
 *  =======================================================*/
if (!function_exists('user_can_safe')) {
  function user_can_safe(...$args): ?bool {
    if (!function_exists('user_can')) return null;
    try {
      $rf  = new ReflectionFunction('user_can');
      $min = $rf->getNumberOfRequiredParameters();
      if (count($args) < $min) return null;
      return (bool) user_can(...$args);
    } catch (Throwable $e) {
      return null;
    }
  }
}

/** =========================================================
 *  Utils gerais de normalização
 *  =======================================================*/
function normalize_role_str($s){
  $s = trim(mb_strtolower((string)$s, 'UTF-8'));
  $s = strtr($s, [
    'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a',
    'é'=>'e','è'=>'e','ê'=>'e','ë'=>'e',
    'í'=>'i','ì'=>'i','î'=>'i','ï'=>'i',
    'ó'=>'o','ò'=>'o','õ'=>'o','ô'=>'o','ö'=>'o',
    'ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u',
    'ç'=>'c'
  ]);
  $s = preg_replace('/\s+/', '', $s);
  return $s;
}
function fuzzy_fix_role($roleNorm){
  $known = ['admin','comercial','logistica','qualidade','producao','fazenda'];
  if (in_array($roleNorm, $known, true)) return $roleNorm;
  $best = null; $bestDist = 99;
  foreach ($known as $k) { $d = levenshtein($roleNorm, $k); if ($d < $bestDist) { $bestDist = $d; $best = $k; } }
  if ($best !== null && $bestDist <= 2) return $best;
  $map = [
    'logistica' => ['logisticaa','logisitca','logistca','logistcia','logística'],
    'producao'  => ['produca','producaoo','produc ao','produção'],
    'comercial' => ['comerical','comerciall'],
    'qualidade' => ['qualida','qualid','qualidadee'],
    'fazenda'   => ['fazend','fazendaa'],
  ];
  foreach ($map as $ok => $alts) if (in_array($roleNorm, $alts, true)) return $ok;
  return $roleNorm;
}
function parse_roles_any($raw): array {
  if ($raw === null || $raw === '') return [];
  if (is_array($raw)) return $raw;
  $s = trim((string)$raw);
  if ($s === '') return [];
  if (($s[0] ?? '') === '[') { $arr = json_decode($s, true); if (is_array($arr)) return $arr; }
  $parts = preg_split('/[;,|]+/', $s);
  return array_map('trim', $parts ?: []);
}

/** =========================================================
 *  Descoberta agressiva de identidade na sessão
 *  =======================================================*/
function _pick_first_nonempty(array $arr, array $keys){
  foreach($keys as $k){ if(isset($arr[$k]) && is_string($arr[$k]) && trim($arr[$k])!=='') return trim($arr[$k]); }
  return null;
}
function _find_nested_user_array($root): ?array {
  if (!is_array($root)) return null;
  $cands = ['user','profile','data','userinfo','account','claims'];
  foreach ($cands as $k) if (isset($root[$k]) && is_array($root[$k])) return $root[$k];
  return null;
}
function _auth_helpers_get_user(): ?array {
  try {
    if (function_exists('auth_current_user')) return auth_current_user();
    if (function_exists('get_authenticated_user')) return get_authenticated_user();
    if (function_exists('current_user')) return current_user();
  } catch (Throwable $e) {}
  return null;
}
function resolve_session_user_identity(): void {
  if (!isset($_SESSION['user']) || !is_array($_SESSION['user'])) {
    $_SESSION['user'] = [];
  }
  $u =& $_SESSION['user'];

  $fromAuth = _auth_helpers_get_user();
  if (is_array($fromAuth)) {
    foreach (['id','user_id','sub','uid'] as $k) if (!isset($u['id']) && isset($fromAuth[$k])) $u['id'] = $fromAuth[$k];
    foreach (['email','mail','upn','preferred_username'] as $k) if (!isset($u['email']) && isset($fromAuth[$k])) $u['email'] = $fromAuth[$k];
    foreach (['name','full_name','display_name','given_name'] as $k) if (!isset($u['name']) && isset($fromAuth[$k])) $u['name'] = $fromAuth[$k];
  }

  $nested = _find_nested_user_array($u);
  if (is_array($nested)) {
    if (!isset($u['id']))    $u['id']    = _pick_first_nonempty($nested, ['id','user_id','sub','uid']);
    if (!isset($u['email'])) $u['email'] = _pick_first_nonempty($nested, ['email','mail','upn','preferred_username','login']);
    if (!isset($u['name']))  $u['name']  = _pick_first_nonempty($nested, ['name','full_name','display_name','given_name','nickname']);
  }

  if (empty($u['id']))    $u['id']    = _pick_first_nonempty($u, ['id','user_id','sub','uid']);
  if (empty($u['email'])) $u['email'] = _pick_first_nonempty($u, ['email','mail','upn','preferred_username','login']);
  if (empty($u['name']))  $u['name']  = _pick_first_nonempty($u, ['name','full_name','display_name','given_name','nickname']);

  if (empty($u['name']) && !empty($u['email'])) $u['name'] = $u['email'];
}

/** =========================================================
 *  DB helpers
 *  =======================================================*/
function db_fetch_user_by_any($id, $email, $username) {
  $sql = "SELECT *
            FROM users
           WHERE 1=0
              OR (:id IS NOT NULL AND id = :id)
              OR (:email IS NOT NULL AND LOWER(email) = LOWER(:email))
              OR (:username IS NOT NULL AND 1=0)
           ORDER BY id ASC
           LIMIT 1";
  $stmt = pdo()->prepare($sql);
  $stmt->execute([
    ':id'       => $id ?: null,
    ':email'    => $email ?: null,
    ':username' => $username ?: null,
  ]);
  return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
function db_fetch_role_slugs_for_user_id(int $userId): array {
  try {
    $stmt = pdo()->prepare("
      SELECT r.slug
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = :uid
    ");
    $stmt->execute([':uid' => $userId]);
    $rows = $stmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
    return array_values(array_unique(array_map('normalize_role_str', $rows)));
  } catch (Throwable $e) {
    return [];
  }
}
function db_fetch_role_slugs_for_email(string $email): array {
  try {
    $stmt = pdo()->prepare("
      SELECT r.slug
        FROM users u
        JOIN user_roles ur ON ur.user_id = u.id
        JOIN roles r ON r.id = ur.role_id
       WHERE LOWER(u.email) = LOWER(:email)
    ");
    $stmt->execute([':email' => $email]);
    $rows = $stmt->fetchAll(PDO::FETCH_COLUMN) ?: [];
    return array_values(array_unique(array_map('normalize_role_str', $rows)));
  } catch (Throwable $e) {
    return [];
  }
}

/** =========================================================
 *  HIDRATAÇÃO DA SESSÃO COM BASE NO BANCO
 *  =======================================================*/
function db_hydrate_session_from_users(): void {
  resolve_session_user_identity();
  try {
    $u = $_SESSION['user'] ?? [];

    $id       = $u['id'] ?? $u['user_id'] ?? null;
    $email    = $u['email'] ?? $u['mail'] ?? $u['upn'] ?? null;
    $username = $u['username'] ?? $u['user_name'] ?? $u['login'] ?? null;

    if (!$id && !$email && !$username) {
      if (!isset($_SESSION['user'])) $_SESSION['user'] = [];
      $_SESSION['user']['roles'] = $_SESSION['user']['roles'] ?? [];
      return;
    }

    $row = db_fetch_user_by_any($id, $email, $username);
    if ($row) {
      $dbName = '';
      foreach (['Name','name','full_name','FullName','display_name','DisplayName'] as $k) {
        if (!empty($row[$k])) { $dbName = trim((string)$row[$k]); break; }
      }
      if ($dbName === '' && !empty($row['email'])) $dbName = $row['email'];

      if (!isset($_SESSION['user'])) $_SESSION['user'] = [];
      if ($dbName !== '') $_SESSION['user']['name'] = $dbName;

      $resolvedRoles = !empty($row['id']) ? db_fetch_role_slugs_for_user_id((int)$row['id']) : [];
    } else {
      $resolvedRoles = $email ? db_fetch_role_slugs_for_email($email) : [];
    }

    $rawRolesLegacy = $_SESSION['user']['roles'] ?? null;
    if ($rawRolesLegacy !== null && !$resolvedRoles) {
      $legacy = parse_roles_any($rawRolesLegacy);
      $legacy = array_map('normalize_role_str', $legacy);
      $legacy = array_map('fuzzy_fix_role', $legacy);
      $resolvedRoles = $legacy;
    }

    $isAdminFlag = null;
    foreach (['IsAdmin','is_admin','admin'] as $k) {
      if (isset($row[$k])) { $isAdminFlag = (int)!!$row[$k]; break; }
      if (isset($u[$k]))   { $isAdminFlag = (int)!!$u[$k];   break; }
    }
    if ($isAdminFlag) $resolvedRoles[] = 'admin';

    $resolvedRoles = array_values(array_unique(array_filter($resolvedRoles, fn($r)=>$r!=='')));
    $_SESSION['user']['roles'] = $resolvedRoles;

  } catch (Throwable $e) {
    if (!isset($_SESSION['user'])) $_SESSION['user'] = [];
    $_SESSION['user']['roles'] = $_SESSION['user']['roles'] ?? [];
  }
}
db_hydrate_session_from_users();

/** =========================================================
 *  Helpers de identidade/roles
 *  =======================================================*/
function session_user_name(): string {
  $u = $_SESSION['user'] ?? [];
  $candidatos = [
    'name','full_name','display_name','displayName','given_name','preferred_username',
    'nome','username','user_name','login','nickname','nick','email'
  ];
  foreach ($candidatos as $k) {
    if (!empty($u[$k]) && is_string($u[$k])) {
      $v = trim((string)$u[$k]);
      if ($v !== '') return $v;
    }
  }
  foreach (['profile','data'] as $wrap) {
    if (!empty($u[$wrap]) && is_array($u[$wrap])) {
      foreach ($candidatos as $k) {
        if (!empty($u[$wrap][$k]) && is_string($u[$wrap][$k])) {
          $v = trim((string)$u[$wrap][$k]);
          if ($v !== '') return $v;
        }
      }
    }
  }
  return '';
}
function extract_roles_from_array($arr){
  $out = [];
  foreach ($arr as $r) {
    if (is_string($r)) {
      $out[] = fuzzy_fix_role(normalize_role_str($r));
    } elseif (is_array($r) && isset($r['name'])) {
      $out[] = fuzzy_fix_role(normalize_role_str($r['name']));
    }
  }
  return $out;
}
function get_user_roles(): array {
  $u = $_SESSION['user'] ?? [];
  $raw = $u['roles'] ?? ($u['role'] ?? null);
  $parts = [];
  if (is_string($raw)) {
    $parts = array_map('trim', preg_split('/[;,|]+/', $raw));
  } elseif (is_array($raw)) {
    $parts = $raw;
  }
  $roles = extract_roles_from_array($parts);
  if (!empty($u['is_admin']) && !in_array('admin', $roles, true)) $roles[] = 'admin';
  if (!$roles && !empty($u['perfil'])) $roles[] = fuzzy_fix_role(normalize_role_str($u['perfil']));
  $roles = array_values(array_unique(array_filter($roles, fn($r)=>$r !== '')));
  return $roles;
}
function user_has_role(string $wanted): bool {
  $roles = get_user_roles();
  return in_array('admin', $roles, true) || in_array(fuzzy_fix_role(normalize_role_str($wanted)), $roles, true);
}

/** =========================================================
 *  CSRF (fallback)
 *  =======================================================*/
if (!function_exists('csrf_token')) {
  function csrf_token(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
  }
}
if (!function_exists('check_csrf')) {
  function check_csrf(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
    $sent = $_POST['csrf'] ?? '';
    $sess = $_SESSION['csrf'] ?? '';
    if (!$sent || !$sess || !hash_equals($sess, $sent)) {
      http_response_code(403);
      exit('Erro de segurança: Token CSRF inválido.');
    }
  }
}
check_csrf();

// --- De-dupe: guarda UIDs já processados nesta sessão ---
if (!isset($_SESSION['processed_uids'])) $_SESSION['processed_uids'] = [];

// --- Helpers tempo e util ---
function hhmm_to_minutes(?string $s): ?int {
  if (!$s) return null;
  $s = trim($s);
  if (!preg_match('/^(\d{1,2}):([0-5]\d)$/', $s, $m)) return null;
  return (int)$m[1] * 60 + (int)$m[2];
}
function minutes_to_hhmm($min): string {
  $min = (int)$min;
  $h = floor($min/60); $m = $min%60;
  return sprintf('%02d:%02d', max(0,$h), max(0,$m));
}
function first_by_tipo(array $rows, array $prefer): ?array {
  $byTipo = [];
  foreach ($rows as $r) { if (!empty($r['tipo'])) $byTipo[$r['tipo']][] = $r; }
  foreach ($prefer as $t) if (!empty($byTipo[$t][0])) return $byTipo[$t][0];
  return $rows[0] ?? null;
}
function has_value($val): bool { if (is_array($val)) return count($val) > 0; return !is_null($val) && $val !== '' && $val !== 0 && $val !== 0.0; }
function badge($ok): string { return $ok ? '<span class="ml-2 inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 border border-emerald-200">✔ Preenchido</span>' : '<span class="ml-2 inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 border border-amber-200">• Pendente</span>'; }
function dot($arr, $path) { if (!$arr) return null; $seg=explode('.',$path); foreach($seg as $s){ if(!is_array($arr)||!array_key_exists($s,$arr)) return null; $arr=$arr[$s]; } return $arr; }
function chip_value($val,$type='num'): string {
  if ($val===null || $val==='') return '';
  if ($type==='money') $txt = 'R$ '.number_format((float)$val,2,',','.');
  elseif ($type==='pct') $txt = number_format((float)$val,2,',','.').'%';
  else $txt = (is_numeric($val)? str_replace('.',',',(string)$val) : (string)$val);
  return '<span class="ml-2 inline-flex items-center text-xs px-2 py-0.5 rounded-full bg-brand-primary/10 text-brand-primary border border-brand-line">'.$txt.'</span>';
}
function num_input($val): string { return ($val===null||$val==='') ? '' : (string)+$val; }

/** =========================================================
 *  Persistência (POST) + PRG — com ENFORCEMENT de ROLE
 *  =======================================================*/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  try {
    // 0) De-dupe por UID de submissão
    $form_uid = $_POST['form_uid'] ?? '';
    if (!$form_uid) throw new Exception('UID do formulário ausente.');
    if (isset($_SESSION['processed_uids'][$form_uid])) {
      header('Location: '.$_SERVER['PHP_SELF'].'?dup=1');
      exit;
    }

    $ref_date = $_POST['ref_date'] ?? '';
    if (!$ref_date) throw new Exception('A data de referência é obrigatória.');

    // Permissões por seção
    $can = [
      'comercial' => user_has_role('comercial') || (user_can_safe('fill','form_comercial') ?? false),
      'logistica' => user_has_role('logistica') || (user_can_safe('fill','form_logistica') ?? false),
      'qualidade' => user_has_role('qualidade') || (user_can_safe('fill','form_qualidade') ?? false),
      'producao'  => user_has_role('producao')  || (user_can_safe('fill','form_producao') ?? false),
      'fazenda'   => user_has_role('fazenda')   || (user_can_safe('fill','form_fazenda') ?? false),
    ];

    // Nome do responsável (sempre da sessão, nunca do POST)
    $sessionResp = trim(session_user_name());
    if ($sessionResp === '' && !empty($_SESSION['user']['email'])) {
      $sessionResp = $_SESSION['user']['email']; // fallback seguro
    }

    // ---------- LOGÍSTICA ----------
    if ($can['logistica']) {
      $tmt_ls_hhmm    = preg_replace('/[^0-9:]/', '', $_POST['l_tmt_ls_hhmm'] ?? '');
      $tmt_ls_min     = hhmm_to_minutes($tmt_ls_hhmm) ?? 0;
      $tmt_truck_hhmm = preg_replace('/[^0-9:]/', '', $_POST['l_tmt_truck_hhmm'] ?? '');
      $tmt_truck_min  = hhmm_to_minutes($tmt_truck_hhmm) ?? 0;
    } else {
      $tmt_ls_hhmm = $tmt_truck_hhmm = '';
      $tmt_ls_min = $tmt_truck_min = 0;
    }

    // ====== PRODUÇÃO ======
    $desc_norm = $carg_norm = [];
    $p_tmd_hhmm = $p_tmc_hhmm = '';
    $p_tmd_min = $p_tmc_min = 0;

    if ($can['producao']) {
      $allowed_desc = ['carreta_ls','truck'];
      $allowed_carg = ['carreta_ls','truck','bitruck','sider'];

      $descargas = json_decode($_POST['p_descargas'] ?? '[]', true) ?: [];
      $cargas    = json_decode($_POST['p_cargas']    ?? '[]', true) ?: [];

      foreach ($descargas as $r) {
        $tipo = strtolower(trim($r['tipo'] ?? ''));
        if (!in_array($tipo, $allowed_desc, true)) continue;
        $hhmm = preg_replace('/[^0-9:]/','', $r['hhmm'] ?? '');
        $min  = hhmm_to_minutes($hhmm) ?? null;
        $desc_norm[] = ['tipo'=>$tipo, 'hhmm'=>$hhmm, 'min'=>$min];
      }
      foreach ($cargas as $r) {
        $tipo = strtolower(trim($r['tipo'] ?? ''));
        if (!in_array($tipo, $allowed_carg, true)) continue;
        $hhmm = preg_replace('/[^0-9:]/','', $r['hhmm'] ?? '');
        $min  = hhmm_to_minutes($hhmm) ?? null;
        $carg_norm[] = ['tipo'=>$tipo, 'hhmm'=>$hhmm, 'min'=>$min];
      }
      $prefDesc   = first_by_tipo($desc_norm, ['carreta_ls']);
      $prefCarg   = first_by_tipo($carg_norm, ['carreta_ls']);
      $p_tmd_hhmm = $prefDesc['hhmm'] ?? '';
      $p_tmd_min  = hhmm_to_minutes($p_tmd_hhmm) ?? 0;
      $p_tmc_hhmm = $prefCarg['hhmm'] ?? '';
      $p_tmc_min  = hhmm_to_minutes($p_tmc_hhmm) ?? 0;
    }

    // ====== Fazenda ======
    $faz_carg_norm = [];
    $f_tmc_hhmm = ''; $f_tmc_min = 0;
    if ($can['fazenda']) {
      $allowed_faz_carg = ['carreta_ls','truck'];
      $faz_cargas = json_decode($_POST['f_carregamentos'] ?? '[]', true) ?: [];
      foreach ($faz_cargas as $r) {
        $tipo = strtolower(trim($r['tipo'] ?? ''));
        if (!in_array($tipo, $allowed_faz_carg, true)) continue;
        $hhmm = preg_replace('/[^0-9:]/','', $r['hhmm'] ?? '');
        $min  = hhmm_to_minutes($hhmm) ?? null;
        $faz_carg_norm[] = ['tipo'=>$tipo, 'hhmm'=>$hhmm, 'min'=>$min];
      }
      $prefFCarg   = first_by_tipo($faz_carg_norm, ['carreta_ls','truck']);
      $f_tmc_hhmm  = $prefFCarg['hhmm'] ?? '';
      $f_tmc_min   = hhmm_to_minutes($f_tmc_hhmm) ?? 0;
    }

    // ====== Qualidade ======
    if ($can['qualidade']) {
      $q_pelada_dia      = (float)($_POST['q_pelada_dia'] ?? 0);
      $q_pelada_media    = (float)($_POST['q_pelada_media'] ?? 0);
      $q_defeitos_dia    = (float)($_POST['q_defeitos_dia'] ?? 0);
      $q_defeitos_media  = (float)($_POST['q_defeitos_media'] ?? 0);
      $q_uniform_dia     = (float)($_POST['q_uniformidade_dia'] ?? 0);
      $q_uniform_media   = (float)($_POST['q_uniformidade_media'] ?? 0);
      $q_pmb_var         = json_decode($_POST['q_pmb_variedade'] ?? '[]', true) ?: [];
      $q_bulbos_var      = json_decode($_POST['q_bulbos_variedade'] ?? '[]', true) ?: [];
    } else {
      $q_pelada_dia=$q_pelada_media=$q_defeitos_dia=$q_defeitos_media=$q_uniform_dia=$q_uniform_media=0.0;
      $q_pmb_var = $q_bulbos_var = [];
    }

    // ====== Comercial ======
    $c_vendas = [];
    if ($can['comercial']) {
      $c_vendas = json_decode($_POST['c_vendas'] ?? '[]', true) ?: [];
    }

    // ====== Romaneio + Aproveitamento automático por variedade (Produção) ======
    $romaneio_rows = [];
    if ($can['producao']) {
      $romaneio_rows = json_decode($_POST['p_romaneio'] ?? '[]', true) ?: [];
    }
    $aprov_por_var = [];
    $tot_uti = 0; $tot_all = 0;
    if ($can['producao']) {
      $agg = [];
      foreach ($romaneio_rows as $r) {
        $var = trim($r['variedade'] ?? '');
        if ($var==='') continue;
        if (!isset($agg[$var])) $agg[$var] = ['cx1'=>0,'cx2'=>0,'cx3'=>0,'cx4'=>0,'cx5'=>0,'residuo'=>0,'refugo'=>0];
        foreach (['cx1','cx2','cx3','cx4','cx5','residuo','refugo'] as $k) $agg[$var][$k] += (int)($r[$k] ?? 0);
      }
      foreach ($agg as $var=>$v) {
        $util = (int)$v['cx1'] + (int)$v['cx2'] + (int)$v['cx3'] + (int)$v['cx4'] + (int)$v['cx5'];
        $den  = $util + (int)$v['residuo'] + (int)$v['refugo'];
        $pct  = $den>0 ? ($util/$den*100.0) : null;
        if ($den>0) { $tot_uti += $util; $tot_all += $den; }
        $aprov_por_var[] = ['variedade'=>$var, 'aprov_pct'=> $pct!==null ? round($pct,2) : null];
      }
    }
    $aprov_geral = $tot_all>0 ? round($tot_uti/$tot_all*100.0, 2) : null;

    $payload = [
      'meta' => [
        'ref_date'    => $ref_date,
        'unidade'     => trim($_POST['unidade'] ?? ''),
        'responsavel' => $sessionResp,
        'observacoes' => trim($_POST['observacoes'] ?? '')
      ],
      'comercial' => [
        'vendas' => $can['comercial'] ? $c_vendas : [],
      ],
      'logistica' => $can['logistica'] ? [
        'transporte' => [
          'carreta_ls' => [ 'hhmm'=>$tmt_ls_hhmm, 'min'=>$tmt_ls_min ],
          'truck'      => [ 'hhmm'=>$tmt_truck_hhmm, 'min'=>$tmt_truck_min ],
        ],
        'tempo_transporte_hhmm' => $tmt_ls_hhmm,
        'tempo_transporte_min'  => $tmt_ls_min,
      ] : [],
      'qualidade' => $can['qualidade'] ? [
        'pelada_pct' => [
          'dia_anterior' => $q_pelada_dia,
          'media_geral'  => $q_pelada_media
        ],
        'defeitos_pct' => [
          'dia_anterior' => $q_defeitos_dia,
          'media_geral'  => $q_defeitos_media
        ],
        'uniformidade_pct' => [
          'dia_anterior' => $q_uniform_dia,
          'media_geral'  => $q_uniform_media
        ],
        'pmb_variedade'         => $q_pmb_var,
        'bulbos_saco_variedade' => $q_bulbos_var,
      ] : [],
      'producao' => $can['producao'] ? [
        'descarregamento' => $desc_norm,
        'carregamento'    => $carg_norm,
        'tempo_descarregamento_hhmm' => $p_tmd_hhmm,
        'tempo_descarregamento_min'  => $p_tmd_min,
        'tempo_carregamento_hhmm'    => $p_tmc_hhmm,
        'tempo_carregamento_min'     => $p_tmc_min,
        'tmd' => [
          'dia_anterior' => (float)$p_tmd_min,
          'media_geral'  => (float)($_POST['p_tmd_media'] ?? 0)
        ],
        'tmc' => [
          'dia_anterior' => (float)$p_tmc_min,
          'media_geral'  => (float)($_POST['p_tmc_media'] ?? 0)
        ],
        'aproveitamento_var_pct' => [
          'dia_anterior' => $aprov_geral !== null ? (float)$aprov_geral : 0.0,
          'media_geral'  => (float)($_POST['p_aprov_media'] ?? ($aprov_geral ?? 0))
        ],
        'aproveitamento_var_por_variedade' => $aprov_por_var,
        'romaneio' => $romaneio_rows,
        'sacos_beneficiados_dia' => [
          'dia_anterior'=>(float)($_POST['p_sacos_benef_dia'] ?? 0),
          'media_geral' =>(float)($_POST['p_sacos_benef_media'] ?? 0)
        ],
        'sacos_por_colaborador' => [
          'dia_anterior'=>(float)($_POST['p_sacos_colab_dia'] ?? 0),
          'media_geral' =>(float)($_POST['p_sacos_colab_media'] ?? 0)
        ],
      ] : [],
      'fazenda' => $can['fazenda'] ? [
        'pessoas_dia' => [
          'dia_anterior'=>(float)($_POST['f_pessoas_dia'] ?? 0),
          'media_geral' =>(float)($_POST['f_pessoas_media'] ?? 0)
        ],
        'bigbag_por_variedade' => json_decode($_POST['f_bigbag_variedade'] ?? '[]', true) ?: [],
        'colhedora_bigbag_dia' => [
          'dia_anterior'=>(float)($_POST['f_colhedora_dia'] ?? 0),
          'media_geral' =>(float)($_POST['f_colhedora_media'] ?? 0)
        ],
        'carregamento' => $faz_carg_norm,
        'tmc_fazenda_hhmm' => $f_tmc_hhmm,
        'tmc_fazenda_min'  => $f_tmc_min,
        'tmc_fazenda' => [
          'dia_anterior'=>(float)$f_tmc_min,
          'media_geral' =>(float)($_POST['f_tmc_media'] ?? 0)
        ],
      ] : [],
    ];

    // Grava no banco
    $stmt = pdo()->prepare('INSERT INTO safra_entries (ref_date, unidade, responsavel, payload_json) VALUES (?,?,?,?)');
    $stmt->execute([
      $ref_date,
      $payload['meta']['unidade'],
      $payload['meta']['responsavel'],
      json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)
    ]);

    $_SESSION['processed_uids'][$form_uid] = time();
    header('Location: '.$_SERVER['PHP_SELF'].'?saved=1&date='.rawurlencode($ref_date).'&view='.rawurlencode($ref_date));
    exit;

  } catch(Throwable $e) {
    $_SESSION['last_error'] = 'Erro ao salvar: '.$e->getMessage();
    header('Location: '.$_SERVER['PHP_SELF'].'?error=1');
    exit;
  }
}

/** =========================================================
 *  Leitura (GET por data de visualização + prefill)
 *  =======================================================*/
$today = date('Y-m-d');
$view = isset($_GET['view']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['view']) ? $_GET['view'] : $today;

$viewPayload = null;
try {
  $q = pdo()->prepare('SELECT payload_json FROM safra_entries WHERE ref_date=? ORDER BY id DESC LIMIT 1');
  $q->execute([$view]);
  if ($row = $q->fetch()) $viewPayload = json_decode($row['payload_json'], true);
} catch(Throwable $e) {
  $viewPayload = [];
}

// Flash via PRG
$flash = ['type'=>null,'msg'=>null];
if (isset($_GET['saved'])) {
  $flash = ['type'=>'success','msg'=>'Registro salvo com sucesso para '.htmlspecialchars($_GET['date'] ?? $view).'.'];
} elseif (isset($_GET['dup'])) {
  $flash = ['type'=>'success','msg'=>'Registro já havia sido processado. Nenhum dado duplicado.'];
} elseif (isset($_GET['error'])) {
  $err = $_SESSION['last_error'] ?? 'Erro inesperado.'; unset($_SESSION['last_error']);
  $flash = ['type'=>'error','msg'=>$err];
}

// Prefill específicos
function render_rows_compact($rows,$cols): string{
  if(!$rows || !is_array($rows) || !count($rows)) return '';
  $th=''; foreach($cols as $k=>$label) $th .= "<th class='px-3 py-2 text-left text-xs text-brand-muted font-semibold uppercase'>$label</th>";
  $trs=''; foreach($rows as $i=>$r){ $tr_class = ($i%2==0)?'bg-white':'bg-brand-bg/50'; $trs.="<tr class='$tr_class'>"; foreach($cols as $k=>$label){ $v=$r[$k]??''; if(is_numeric($v)) $v=str_replace('.',',',$v); $trs.="<td class='px-3 py-2 text-sm'>$v</td>"; } $trs.='</tr>'; }
  return "<div class='mt-2 border border-brand-line rounded-lg overflow-hidden'><table class='min-w-full'><thead class='bg-brand-bg'><tr>$th</tr></thead><tbody>$trs</tbody></table></div>";
}

$prefill = [
  // Logística
  'l_tmt_ls_hhmm'   => dot($viewPayload,'logistica.transporte.carreta_ls.hhmm') ?: (dot($viewPayload,'logistica.tempo_transporte_hhmm') ?? ''),
  'l_tmt_truck_hhmm'=> dot($viewPayload,'logistica.transporte.truck.hhmm') ?: '',

  // Produção — repetidores
  'p_descargas' => dot($viewPayload,'producao.descarregamento') ?: (function() use ($viewPayload){
      $hh = dot($viewPayload,'producao.tempo_descarregamento_hhmm');
      return $hh ? [['tipo'=>'carreta_ls','hhmm'=>$hh,'min'=>hhmm_to_minutes($hh)]] : [];
  })(),
  'p_cargas'    => dot($viewPayload,'producao.carregamento') ?: (function() use ($viewPayload){
      $hh = dot($viewPayload,'producao.tempo_carregamento_hhmm');
      return $hh ? [['tipo'=>'carreta_ls','hhmm'=>$hh,'min'=>hhmm_to_minutes($hh)]] : [];
  })(),

  // Fazenda — repetidor (novo) com fallback ao legado
  'f_cargas' => dot($viewPayload,'fazenda.carregamento') ?: (function() use ($viewPayload){
      $hh = dot($viewPayload,'fazenda.tmc_fazenda_hhmm')
            ?: (dot($viewPayload,'fazenda.tmc_fazenda.dia_anterior')!==null
                ? minutes_to_hhmm(dot($viewPayload,'fazenda.tmc_fazenda.dia_anterior')) : '');
      return $hh ? [['tipo'=>'carreta_ls','hhmm'=>$hh,'min'=>hhmm_to_minutes($hh)]] : [];
  })(),
];

// Prefill para JS
$savedRepeaterData = [
  'cVendas'        => dot($viewPayload,'comercial.vendas') ?: [],
  'qPMBVar'        => dot($viewPayload,'qualidade.pmb_variedade') ?: [],
  'qBulbosVar'     => dot($viewPayload,'qualidade.bulbos_saco_variedade') ?: [],
  'pAprovVar'      => dot($viewPayload,'producao.aproveitamento_var_por_variedade') ?: [],
  'pRomaneio'      => dot($viewPayload,'producao.romaneio') ?: [],
  'fBigBagVar'     => dot($viewPayload,'fazenda.bigbag_por_variedade') ?: [],
  'pDescargas'     => $prefill['p_descargas'],
  'pCargas'        => $prefill['p_cargas'],
  'fCarregamentos' => $prefill['f_cargas'],
];

// UID para o próximo envio
$form_uid = bin2hex(random_bytes(16));

// Nome do usuário logado para o campo "Responsável"
$sessionResp = trim(session_user_name());
if ($sessionResp === '' && !empty($_SESSION['user']['email'])) {
  $sessionResp = $_SESSION['user']['email'];
}

// Permissões para a VIEW (com capabilities extras)
$can = [
  'comercial' => user_has_role('comercial') || (user_can_safe('fill','form_comercial') ?? false),
  'logistica' => user_has_role('logistica') || (user_can_safe('fill','form_logistica') ?? false),
  'qualidade' => user_has_role('qualidade') || (user_can_safe('fill','form_qualidade') ?? false),
  'producao'  => user_has_role('producao')  || (user_can_safe('fill','form_producao') ?? false),
  'fazenda'   => user_has_role('fazenda')   || (user_can_safe('fill','form_fazenda') ?? false),
];
$hasAnyRole = in_array(true, $can, true);

// [NOVO] Admin por role ou por capability
$isAdminByRole = user_has_role('admin');
$isAdminByCap  = (user_can_safe('admin','system') ?? false) || (user_can_safe('manage','system') ?? false);
$isAdmin       = $isAdminByRole || $isAdminByCap;

// [VARIEDADE] calcular permissão, mas SEM esconder o botão
$canAccessDashVariedade =
  $isAdmin
  || $can['qualidade']
  || $can['producao']
  || $can['fazenda']
  || (user_can_safe('view','dashboard_qualidade') ?? false)
  || (user_can_safe('view','dashboard_producao')  ?? false)
  || (user_can_safe('view','dashboard_fazenda')   ?? false);

// aba padrão = primeira permitida numa ordem amigável
$tabOrder = ['logistica','comercial','qualidade','producao','fazenda'];
$defaultTab = 'logistica';
foreach ($tabOrder as $t) { if (!empty($can[$t])) { $defaultTab = $t; break; } }
?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Safra Cebola 25/26</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: { extend: {
        fontFamily: { sans: ['Nunito','ui-sans-serif','system-ui'] },
        colors: { brand: { bg:'#F9FAFB', surface:'#FFFFFF', line:'#E0E7E0', primary:'#5FB141', primaryDark:'#3C8F28', text:'#273418', muted:'#6B7280' } },
        borderRadius: { lg:'0.75rem', xl:'1rem', '2xl':'1.5rem' },
        boxShadow: { 'soft-green':'0 10px 25px -5px rgba(95,177,65,.08), 0 4px 8px -1 rgba(95,177,65,.1)' }
      } }
    }
  </script>
  <style>
    body { background-color:#F9FAFB; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
    input[type="number"]{ text-align:right; }
    .grid-auto-fit{ display:grid; gap:.75rem; }
    @media (min-width:768px){ .grid-auto-fit{ grid-template-columns:repeat(auto-fit, minmax(180px,1fr)); } }
    .col-full{ grid-column:1 / -1; }
    #toast-root { position: fixed; right: 1rem; bottom: 1rem; display: flex; flex-direction: column; gap: .75rem; z-index: 9999; }
  </style>
  <?php render_datepicker_assets(); ?>
</head>
<body class="text-brand-text bg-brand-bg">
  <!-- Nav -->
 <?php render_boden_navbar('form'); ?>
  <div class="max-w-7xl mx-auto p-6 lg:p-10">
    <header class="mb-4 mt-2">
      <div class="flex items-center justify-between gap-4">
        <div class="flex items-center gap-4">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center"><span class="text-4xl">🧅</span></div>
          <div>
            <h1 class="text-2xl font-bold text-brand-text">Safra Cebola 25/26</h1>
            <p class="text-brand-muted text-sm">Mostrando dados de <strong><?php echo (new DateTime($view))->format('d/m/Y'); ?></strong></p>
          </div>
        </div>

        <!-- Filtro de visualização por dia -->
        <form method="GET" class="flex items-center gap-2">
          <button type="button" onclick="location.href='<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?view='.(new DateTime($view))->modify('-1 day')->format('Y-m-d')); ?>'" class="h-10 w-10 inline-flex items-center justify-center rounded-lg border border-brand-line bg-white hover:bg-brand-bg" title="Dia anterior" aria-label="Dia anterior">◀</button>
          <input id="view" type="date" name="view" value="<?php echo htmlspecialchars($view); ?>" class="h-10 px-3 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
          <button type="button" onclick="location.href='<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?view='.(new DateTime($view))->modify('+1 day')->format('Y-m-d')); ?>'" class="h-10 w-10 inline-flex items-center justify-center rounded-lg border border-brand-line bg-white hover:bg-brand-bg" title="Próximo dia" aria-label="Próximo dia">▶</button>
          <button class="h-10 px-4 rounded-lg bg-brand-primary text-white font-semibold hover:bg-brand-primaryDark">Aplicar</button>
          <a class="h-10 px-4 inline-flex items-center justify-center rounded-lg border border-brand-line bg-white hover:bg-brand-bg" href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'].'?view='.$today); ?>">Hoje</a>
        </form>
      </div>
    </header>

    <!-- Aviso de falta de permissão/identidade -->
    <?php if (!$hasAnyRole): ?>
      <div class="mb-6 p-4 border border-amber-300 bg-amber-50 rounded-xl">
        <p class="text-sm text-amber-800">
          Não foi possível determinar suas permissões. Verifique se o usuário autenticado existe na tabela <code>users</code> e possui vínculos em <code>user_roles</code>.
          Caso já exista, confira se o e-mail na sessão coincide com o e-mail no banco.
        </p>
      </div>
    <?php endif; ?>

    <!-- Toast -->
    <div id="toast-root" aria-live="polite" aria-atomic="true"></div>

    <form method="POST" id="safraForm" class="space-y-8" autocomplete="off">
      <input type="hidden" name="csrf" value="<?php echo htmlspecialchars(csrf_token()); ?>" />
      <input type="hidden" name="form_uid" value="<?php echo htmlspecialchars($form_uid); ?>" />

      <!-- Meta -->
      <section class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8">
        <div class="grid md:grid-cols-3 gap-6">
          <div>
            <label class="block text-sm font-medium text-brand-muted mb-2">Data de referência *</label>
            <input type="date" name="ref_date" required class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" value="<?php echo htmlspecialchars($view); ?>" />
          </div>
          <div class="md:col-span-2">
            <label class="block text-sm font-medium text-brand-text mb-2 flex items-center gap-2">
              Responsável
            </label>
            <input type="text" value="<?php echo htmlspecialchars($sessionResp ?: ''); ?>" readonly aria-readonly="true"
                   class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg text-brand-text font-semibold"
                   placeholder=""/>
          </div>
          <div class="md:col-span-3">
            <?php $vObs = dot($viewPayload,'meta.observacoes'); ?>
            <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">Observações</label>
            <textarea name="observacoes" rows="2" class="block w-full px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" placeholder="Notas gerais, imprevistos ou destaques do dia..."><?php echo htmlspecialchars($vObs ?? ''); ?></textarea>
          </div>
        </div>
      </section>

      <!-- Tabs (somente as que o usuário pode ver) -->
      <nav class="flex flex-wrap gap-3">
        <?php if ($can['comercial']): ?><button type="button" data-tab="comercial" class="tab px-5 py-2 rounded-full border text-sm font-semibold transition-all">Comercial</button><?php endif; ?>
        <?php if ($can['logistica']): ?><button type="button" data-tab="logistica" class="tab px-5 py-2 rounded-full border text-sm font-semibold transition-all">Logística</button><?php endif; ?>
        <?php if ($can['qualidade']): ?><button type="button" data-tab="qualidade" class="tab px-5 py-2 rounded-full border text-sm font-semibold transition-all">Qualidade</button><?php endif; ?>
        <?php if ($can['producao']): ?><button type="button" data-tab="producao"  class="tab px-5 py-2 rounded-full border text-sm font-semibold transition-all">Produção</button><?php endif; ?>
        <?php if ($can['fazenda']): ?><button type="button" data-tab="fazenda"   class="tab px-5 py-2 rounded-full border text-sm font-semibold transition-all">Fazenda</button><?php endif; ?>
      </nav>

      <!-- Comercial -->
      <?php if ($can['comercial']): ?>
      <section id="tab-comercial" class="tab-pane hidden">
        <div class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8 space-y-6">
          <h2 class="text-xl font-bold text-brand-text">Comercial</h2>
          <?php
            $rowsC = dot($viewPayload,'comercial.vendas') ?: [];
            $rowsC_disp = [];
            foreach ($rowsC as $r) {
              $rowsC_disp[] = [
                'caixa'        => $r['caixa'] ?? '',
                'variedade'    => $r['variedade'] ?? '',
                'preco_ontem'  => $r['preco_ontem'] ?? ($r['preco'] ?? ''),
                'preco_hoje'   => $r['preco_hoje']  ?? '',
              ];
            }
            $okC = has_value($rowsC_disp);
          ?>
          <div class="flex items-center mb-3 gap-3">
            <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
              Valor da Venda do Dia (Caixa + Variedade + Preços)
              <span class="inline-flex items-center">
                <?php echo badge($okC); ?>
                <button type="button" class="add-row text-xs ml-2 px-3 py-1 rounded-full bg-white border border-brand-line text-brand-text hover:bg-brand-bg hover:border-brand-primary/50 transition-colors" data-target="cVendas">Adicionar</button>
              </span>
            </label>
          </div>
          <?php echo render_rows_compact($rowsC_disp,[ 'caixa'=>'Caixa','variedade'=>'Variedade','preco_ontem'=>'Preço Ontem (R$)','preco_hoje'=>'Preço Hoje (R$)' ]); ?>
          <div id="cVendas" class="space-y-3 mt-3"></div>
          <input type="hidden" name="c_vendas" id="c_vendas_json" />
        </div>
      </section>
      <?php endif; ?>

      <!-- Logística -->
      <?php if ($can['logistica']): ?>
      <section id="tab-logistica" class="tab-pane hidden">
        <div class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8 space-y-6">
          <h2 class="text-xl font-bold text-brand-text">Logística</h2>
          <?php
            $vLls  = $prefill['l_tmt_ls_hhmm'];
            $vLtrk = $prefill['l_tmt_truck_hhmm'];
            $okLls = has_value($vLls);
            $okLtr = has_value($vLtrk);
          ?>
          <div class="grid md:grid-cols-2 gap-6">
            <div>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">
                Tempo de Transporte (HH:MM) — <strong>Carreta LS</strong>
                <?php echo badge($okLls).chip_value($vLls,'num'); ?>
              </label>
              <input type="time" step="60" name="l_tmt_ls_hhmm"
                     value="<?php echo htmlspecialchars($vLls ?? ''); ?>"
                     class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
            <div>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">
                Tempo de Transporte (HH:MM) — <strong>Truck</strong>
                <?php echo badge($okLtr).chip_value($vLtrk,'num'); ?>
              </label>
              <input type="time" step="60" name="l_tmt_truck_hhmm"
                     value="<?php echo htmlspecialchars($vLtrk ?? ''); ?>"
                     class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
          </div>
        </div>
      </section>
      <?php endif; ?>

      <!-- Qualidade -->
      <?php if ($can['qualidade']): ?>
      <section id="tab-qualidade" class="tab-pane hidden">
        <div class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8 space-y-8">
          <h2 class="text-xl font-bold text-brand-text">Qualidade</h2>
          <div class="grid md:grid-cols-3 gap-6 items-start">
            <div>
              <?php $vQ6d = dot($viewPayload,'qualidade.pelada_pct.dia_anterior'); $okQ6d = has_value($vQ6d); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">Cebola Pelada (%) <?php echo badge($okQ6d).chip_value($vQ6d,'pct'); ?></label>
              <input type="number" step="0.01" min="0" max="100" inputmode="decimal" name="q_pelada_dia" value="<?php echo htmlspecialchars(num_input($vQ6d)); ?>" class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
            <div>
              <?php $vQ7d = dot($viewPayload,'qualidade.defeitos_pct.dia_anterior'); $okQ7d = has_value($vQ7d); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex itens-center gap-2">Cebola com Defeitos (%) <?php echo badge($okQ7d).chip_value($vQ7d,'pct'); ?></label>
              <input type="number" step="0.01" min="0" max="100" inputmode="decimal" name="q_defeitos_dia" value="<?php echo htmlspecialchars(num_input($vQ7d)); ?>" class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
            <div>
              <?php $vQ8d = dot($viewPayload,'qualidade.uniformidade_pct.dia_anterior'); $okQ8d = has_value($vQ8d); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">Uniformidade (%) <?php echo badge($okQ8d).chip_value($vQ8d,'pct'); ?></label>
              <input type="number" step="0.01" min="0" max="100" inputmode="decimal" name="q_uniformidade_dia" value="<?php echo htmlspecialchars(num_input($vQ8d)); ?>" class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outlinenone focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
          </div>

          <div class="grid md:grid-cols-2 gap-x-6 gap-y-8">
            <div>
              <?php $rowsQ9 = dot($viewPayload,'qualidade.pmb_variedade') ?: []; $okQ9 = has_value($rowsQ9); ?>
              <div class="flex items-center mb-3 gap-3">
                <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
                  PMB por variedade
                  <span class="inline-flex items-center">
                    <?php echo badge($okQ9); ?>
                    <button type="button" class="add-row text-xs ml-2 px-3 py-1 rounded-full bg-white border border-brand-line text-brand-text hover:bg-brand-bg hover:border-brand-primary/50 transition-colors" data-target="qPMBVar">Adicionar</button>
                  </span>
                </label>
              </div>
              <?php echo render_rows_compact($rowsQ9,[ 'variedade'=>'Variedade','pmb'=>'PMB (kg)' ]); ?>
              <div id="qPMBVar" class="space-y-3 mt-3"></div>
              <input type="hidden" name="q_pmb_variedade" id="q_pmb_variedade_json" />
            </div>

            <div>
              <?php $rowsQ10 = dot($viewPayload,'qualidade.bulbos_saco_variedade') ?: []; $okQ10 = has_value($rowsQ10); ?>
              <div class="flex items-center mb-3 gap-3">
                <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
                  Nº bulbos/saco
                  <span class="inline-flex items-center">
                    <?php echo badge($okQ10); ?>
                    <button type="button" class="add-row text-xs ml-2 px-3 py-1 rounded-full bg-white border border-brand-line text-brand-text hover:bg-brand-bg hover:border-brand-primary/50 transition-colors" data-target="qBulbosVar">Adicionar</button>
                  </span>
                </label>
              </div>
              <?php echo render_rows_compact($rowsQ10,[ 'variedade'=>'Variedade','bulbos_saco'=>'Bulbos/saco' ]); ?>
              <div id="qBulbosVar" class="space-y-3 mt-3"></div>
              <input type="hidden" name="q_bulbos_variedade" id="q_bulbos_variedade_json" />
            </div>
          </div>
        </div>
      </section>
      <?php endif; ?>

      <!-- Produção -->
      <?php if ($can['producao']): ?>
      <section id="tab-producao" class="tab-pane hidden">
        <div class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8 space-y-8">
          <h2 class="text-xl font-bold text-brand-text">Produção</h2>

          <!-- Descarregamento (repetidor) -->
          <div class="space-y-3">
            <div class="flex items-center justify-between">
              <h3 class="text-base font-semibold">Descarregamento (HH:MM)</h3>
              <div class="flex gap-2">
                <button type="button" class="btn-add-desc px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="carreta_ls">Adicionar Carreta LS</button>
                <button type="button" class="btn-add-desc px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="truck">Adicionar Truck</button>
              </div>
            </div>
            <div id="pDescargas" class="space-y-3"></div>
            <input type="hidden" name="p_descargas" id="p_descargas_json" />
          </div>

          <!-- Carregamento (repetidor) -->
          <div class="space-y-3">
            <div class="flex items-center justify-between">
              <h3 class="text-base font-semibold">Carregamento (HH:MM)</h3>
              <div class="flex gap-2">
                <button type="button" class="btn-add-carg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="carreta_ls">Carreta LS</button>
                <button type="button" class="btn-add-carg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="truck">Truck</button>
                <button type="button" class="btn-add-carg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="bitruck">Bitruck</button>
                <button type="button" class="btn-add-carg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="sider">Sider</button>
              </div>
            </div>
            <div id="pCargas" class="space-y-3"></div>
            <input type="hidden" name="p_cargas" id="p_cargas_json" />
          </div>

          <!-- Aproveitamento geral (auto) -->
          <div class="grid md:grid-cols-3 gap-6">
            <div class="md:col-span-3">
              <?php $vP13m = dot($viewPayload,'producao.aproveitamento_var_pct.dia_anterior'); $okP13m = has_value($vP13m); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">
                Aproveitamento (%) — geral do dia (auto pelo Romaneio)
                <?php echo badge($okP13m).chip_value($vP13m,'pct'); ?>
              </label>
              <input id="p_aprov_media_input" readonly type="number" step="0.01" min="0" max="100" inputmode="decimal" name="p_aprov_media" value="<?php echo htmlspecialchars(num_input($vP13m)); ?>" class="block w-full h-11 px-4 py-2 bg-brand-bg border border-brand-line rounded-lg text-brand-muted" />
            </div>
          </div>

          <!-- Aproveitamento por variedade (auto) -->
          <?php $rowsP13 = dot($viewPayload,'producao.aproveitamento_var_por_variedade') ?: []; $okP13 = has_value($rowsP13); ?>
          <div class="pt-2">
            <div class="flex items-center mb-3 gap-3">
              <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
                Aproveitamento por variedade (%) — automático via Romaneio
                <span class="inline-flex items-center"><?php echo badge($okP13); ?></span>
              </label>
            </div>
            <?php echo render_rows_compact($rowsP13,[ 'variedade'=>'Variedade','aprov_pct'=>'% Aproveitamento' ]); ?>
            <div id="pAprovVar" class="space-y-3 mt-3"></div>
            <input type="hidden" name="p_aprov_variedades" id="p_aprov_variedades_json" />
          </div>

          <!-- Romaneio -->
          <?php $rowsP14 = dot($viewPayload,'producao.romaneio') ?: []; $okP14 = has_value($rowsP14); ?>
          <div class="pt-2">
            <div class="flex items-center mb-3 gap-3">
              <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
                Romaneio por variedade
                <span class="inline-flex items-center">
                  <?php echo badge($okP14); ?>
                  <button type="button" class="add-row text-xs ml-2 px-3 py-1 rounded-full bg-white border border-brand-line text-brand-text hover:bg-brand-bg hover:border-brand-primary/50 transition-colors" data-target="pRomaneio">Adicionar</button>
                </span>
              </label>
            </div>
            <?php echo render_rows_compact($rowsP14,[ 'variedade'=>'Variedade','cx1'=>'Cx1','cx2'=>'Cx2','cx3'=>'Cx3','cx4'=>'Cx4','cx5'=>'Cx5','residuo'=>'Resíduo','refugo'=>'Refugo' ]); ?>
            <div id="pRomaneio" class="space-y-3 mt-3"></div>
            <input type="hidden" name="p_romaneio" id="p_romaneio_json" />
          </div>
        </div>
      </section>
      <?php endif; ?>

      <!-- Fazenda -->
      <?php if ($can['fazenda']): ?>
      <section id="tab-fazenda" class="tab-pane hidden">
        <div class="bg-brand-surface border border-brand-line rounded-2xl p-6 lg:p-8 space-y-8">
          <h2 class="text-xl font-bold text-brand-text">Fazenda</h2>

          <div class="grid md:grid-cols-3 gap-6">
            <div>
              <?php $vF17d = dot($viewPayload,'fazenda.pessoas_dia.dia_anterior'); $okF17d = has_value($vF17d); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">Pessoas no Campo<?php echo badge($okF17d).chip_value($vF17d,'num'); ?></label>
              <input type="number" min="0" step="1" name="f_pessoas_dia" value="<?php echo htmlspecialchars(num_input($vF17d)); ?>" class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>
            <div>
              <?php $vF19d = dot($viewPayload,'fazenda.colhedora_bigbag_dia.dia_anterior'); $okF19d = has_value($vF19d); ?>
              <label class="block text-sm font-medium text-brand-muted mb-2 flex items-center gap-2">Colhedora Big Bag/Dia <?php echo badge($okF19d).chip_value($vF19d,'num'); ?></label>
              <input type="number" min="0" step="1" name="f_colhedora_dia" value="<?php echo htmlspecialchars(num_input($vF19d)); ?>" class="block w-full h-11 px-4 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary" />
            </div>

            <!-- Carregamento Fazenda (repetidor por tipo) -->
            <div class="md:col-span-3 space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold">Carregamento Fazenda (HH:MM)</h3>
                <div class="flex gap-2">
                  <button type="button" class="btn-add-fcarg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="carreta_ls">Adicionar Carreta LS</button>
                  <button type="button" class="btn-add-fcarg px-3 py-1.5 text-xs rounded-full border border-brand-line bg-white hover:bg-brand-bg" data-tipo="truck">Adicionar Truck</button>
                </div>
              </div>
              <div id="fCarregamentos" class="space-y-3"></div>
              <input type="hidden" name="f_carregamentos" id="f_carregamentos_json" />
              <p class="text-xs text-brand-muted">Observação: os campos legados de TMC Fazenda continuam sendo calculados a partir do primeiro registro (preferência Carreta LS).</p>
            </div>
          </div>

          <?php $rowsF18 = dot($viewPayload,'fazenda.bigbag_por_variedade') ?: []; $okF18 = has_value($rowsF18); ?>
          <div>
            <div class="flex items-center mb-3 gap-3">
              <label class="text-sm font-medium text-brand-muted flex items-center gap-2">
                Big bag/dia por variedade
                <span class="inline-flex items-center">
                  <?php echo badge($okF18); ?>
                  <button type="button" class="add-row text-xs ml-2 px-3 py-1 rounded-full bg-white border border-brand-line text-brand-text hover:bg-brand-bg hover:border-brand-primary/50 transition-colors" data-target="fBigBagVar">Adicionar</button>
                </span>
              </label>
            </div>
            <?php echo render_rows_compact($rowsF18,[ 'variedade'=>'Variedade','bigbag_dia'=>'Big bag/dia']); ?>
            <div id="fBigBagVar" class="space-y-3 mt-3"></div>
            <input type="hidden" name="f_bigbag_variedade" id="f_bigbag_variedade_json" />
          </div>
        </div>
      </section>
      <?php endif; ?>

      <!-- Ações -->
      <div class="flex items-center justify-end gap-4 pt-2">
        <button type="reset" class="px-6 py-2 rounded-full font-semibold text-brand-muted bg-white border border-brand-line hover:bg-brand-bg hover:text-brand-text transition-colors">Limpar</button>
        <button type="submit" class="px-8 py-2 rounded-full bg-brand-primary text-white font-semibold hover:bg-brand-primaryDark transition-all">Salvar Registro</button>
      </div>
    </form>

    <footer class="mt-12 pt-8 border-t border-brand-line text-center">
      <p class="text-sm text-brand-muted">Powered by TI - Grupo W3 © <?php echo date('Y'); ?></p>
    </footer>
  </div>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const initialData = <?php echo json_encode($savedRepeaterData, JSON_NUMERIC_CHECK|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  window.__flash = <?php echo json_encode($flash, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const DEFAULT_TAB = <?php echo json_encode($defaultTab); ?>;

  function showToast(type, message, timeoutMs = 5000) {
    if (!message) return;
    const root = document.getElementById('toast-root');
    const wrap = document.createElement('div');
    wrap.role = 'status';
    wrap.className = 'toast-enter p-4 min-w-[260px] max-w-[360px] rounded-xl border bg-white';
    wrap.style.borderColor = type === 'success' ? '#A7F3D0' : '#FECACA';
    const colorCls = type === 'success' ? 'text-emerald-700' : 'text-rose-700';
    const badgeBg  = type === 'success' ? 'bg-emerald-100' : 'bg-rose-100';
    const icon     = type === 'success' ? '✅' : '⚠️';
    wrap.innerHTML = `
      <div class="flex items-start gap-3">
        <div class="shrink-0 ${badgeBg} rounded-lg w-8 h-8 flex items-center justify-center" aria-hidden="true">${icon}</div>
        <div class="flex-1">
          <p class="text-sm ${colorCls} font-semibold mb-1">${type === 'success' ? 'Sucesso' : 'Atenção'}</p>
          <p class="text-sm text-brand-text leading-snug">${escapeHtml(message)}</p>
        </div>
        <button type="button" aria-label="Fechar" class="ml-2 text-brand-muted hover:text-brand-text text-xl leading-none">&times;</button>
      </div>
    `;
    const closeBtn = wrap.querySelector('button');
    closeBtn.addEventListener('click', () => wrap.remove());
    root.appendChild(wrap);
    setTimeout(()=>wrap.remove(), timeoutMs);
  }
  function escapeHtml(s) { return s.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
  if (window.__flash && window.__flash.type && window.__flash.msg) showToast(window.__flash.type, window.__flash.msg);

  // [VARIEDADE] Intercepta clique quando não permitido
  const linkVar = document.getElementById('linkDashVariedade');
  if (linkVar && linkVar.dataset.allowed !== '1') {
    linkVar.addEventListener('click', (e) => {
      e.preventDefault();
      showToast('error', 'Você não tem permissão para acessar o Dashboard de Variedade.');
    });
  }

  const tabs = document.querySelectorAll('.tab');
  const panes = {
    comercial: document.getElementById('tab-comercial'),
    logistica: document.getElementById('tab-logistica'),
    qualidade: document.getElementById('tab-qualidade'),
    producao : document.getElementById('tab-producao'),
    fazenda  : document.getElementById('tab-fazenda')
  };
  const active = ['bg-brand-primary','border-brand-primary','text-white','shadow-md'];
  const inactive = ['bg-white','border-brand-line','text-brand-muted','hover:bg-brand-bg','hover:text-brand-text'];
  tabs.forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const t = btn.dataset.tab;
      tabs.forEach(b=>{ b.classList.remove(...active); b.classList.add(...inactive); });
      btn.classList.add(...active); btn.classList.remove(...inactive);
      Object.entries(panes).forEach(([k,el])=> el?.classList.toggle('hidden', k!==t));
    });
  });
  document.querySelector(`.tab[data-tab="${DEFAULT_TAB}"]`)?.click();

  const repLabelClass = 'block text-xs font-medium text-brand-muted';
  const repInputClass = 'block w-full h-10 px-3 py-2 bg-white border border-brand-line rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-primary/30 focus:border-brand-primary';

  function createVarRow(fields, onChange, values = {}) {
    const wrap = document.createElement('div');
    wrap.className = 'grid-auto-fit p-3 border border-brand-line rounded-lg bg-brand-bg/30';
    fields.forEach(f=>{
      const div = document.createElement('div');
      const label = document.createElement('label');
      label.className = repLabelClass; label.textContent = f.label;
      let el = document.createElement(f.type === 'select' ? 'select' : 'input');
      el.className = repInputClass + ' mt-1';
      if (f.type !== 'select') {
        el.type = f.type || 'text';
        if (f.attrs) Object.entries(f.attrs).forEach(([k,v])=> el.setAttribute(k,v));
        if (el.type === 'number') el.inputMode='decimal';
      } else {
        (f.options||[]).forEach(opt=>{
          const o=document.createElement('option');
          if(typeof opt==='object'){ o.value=opt.value??''; o.textContent=opt.label??''; }
          else { o.value=opt; o.textContent=opt; }
          el.appendChild(o);
        });
      }
      el.name = f.name;
      if (values[f.name] !== undefined && values[f.name] !== null) el.value = String(values[f.name]);
      el.addEventListener('input', onChange);
      if (f.onInit) f.onInit(el, values);
      div.appendChild(label); div.appendChild(el); wrap.appendChild(div);
    });
    const rm = document.createElement('button');
    rm.type='button'; rm.className='col-full mt-2 text-red-500 hover:text-red-700 text-xs font-medium self-end justify-self-end w-max ml-auto';
    rm.textContent='Remover linha';
    rm.addEventListener('click', ()=>{ wrap.remove(); onChange(); });
    wrap.appendChild(rm);
    return wrap;
  }

  function bindRepeater(containerId, hiddenInputId, fields){
    const container = document.getElementById(containerId);
    const hidden    = document.getElementById(hiddenInputId);
    if (!container || !hidden) return { add(){}, snap(){}, clear(){}, setRows(){} };
    function snapshot(){
      const rows=[]; container.querySelectorAll(':scope > div').forEach(row=>{
        const obj={}; let hasValue=false;
        row.querySelectorAll('input,select').forEach(inp=>{
          let val = inp.value.trim();
          if (inp.tagName==='SELECT') { obj[inp.name]=val; if(val!=='') hasValue=true; return; }
          if (inp.type==='time') { obj[inp.name]=val; if(val!=='') hasValue=true; return; }
          if (inp.type==='number' && val!==''){ obj[inp.name]=parseFloat(val); hasValue=true; }
          else if (val!==''){ obj[inp.name]=val; hasValue=true; }
          else { obj[inp.name]=val; }
        });
        if (hasValue) rows.push(obj);
      });
      hidden.value = JSON.stringify(rows);
      return rows;
    }
    function add(values={}){ container.appendChild(createVarRow(fields, ()=>snapshot(), values)); snapshot(); }
    function clear(){ container.innerHTML=''; snapshot(); }
    function setRows(rows=[]){ clear(); rows.forEach(r=>add(r)); snapshot(); }
    return { add, snap:snapshot, clear, setRows };
  }

  const CAIXAS     = ['Caixa 1','Caixa 2','Caixa 3','Caixa 4','Caixa 5'];
  const VARIEDADES = ['Mirela','Madalin','Topazio','Robusta','Karaja','Vale Sul','Lucinda','Irati','Salto Grande'];
  const TIPOS_DESC = [{value:'carreta_ls',label:'Carreta LS'},{value:'truck',label:'Truck'}];
  const TIPOS_CARG = [{value:'carreta_ls',label:'Carreta LS'},{value:'truck',label:'Truck'},{value:'bitruck',label:'Bitruck'},{value:'sider',label:'Sider'}];
  const TIPOS_FAZ_CARG = [{value:'carreta_ls',label:'Carreta LS'},{value:'truck',label:'Truck'}];

  const repeaters = {
    cVendas: bindRepeater('cVendas','c_vendas_json',[
      { name:'caixa',        label:'Caixa',             type:'select', options: CAIXAS },
      { name:'variedade',    label:'Variedade',         type:'select', options: VARIEDADES },
      { name:'preco_ontem',  label:'Preço Ontem (R$)',  type:'number', attrs:{ step:'0.01', min:'0', inputmode:'decimal' } },
      { name:'preco_hoje',   label:'Preço Hoje (R$)',   type:'number', attrs:{ step:'0.01', min:'0', inputmode:'decimal' } },
    ]),
    qPMBVar: bindRepeater('qPMBVar','q_pmb_variedade_json',[
      { name:'variedade', label:'Variedade', type:'select', options: VARIEDADES },
      { name:'pmb',       label:'PMB (kg)', type:'number', attrs:{ step:'0.001', min:'0', inputmode:'decimal' } },
    ]),
    qBulbosVar: bindRepeater('qBulbosVar','q_bulbos_variedade_json',[
      { name:'variedade',   label:'Variedade', type:'select', options: VARIEDADES },
      { name:'bulbos_saco', label:'Bulbos / saco', type:'number', attrs:{ step:'1', min:'0' } },
    ]),
    pAprovVar: bindRepeater('pAprovVar','p_aprov_variedades_json',[
      { name:'variedade', label:'Variedade', type:'select', options: VARIEDADES, onInit:(el)=>{ el.disabled=true; } },
      { name:'aprov_pct', label:'% Aproveitamento', type:'number', attrs:{ step:'0.01', min:'0', max:'100', inputmode:'decimal', readOnly:true }, onInit:(el)=>{ el.readOnly=true; el.classList.add('bg-brand-bg'); } },
    ]),
    pRomaneio: bindRepeater('pRomaneio','p_romaneio_json',[
      { name:'variedade', label:'Variedade', type:'select', options: VARIEDADES },
      { name:'cx1', label:'Cx 1', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'cx2', label:'Cx 2', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'cx3', label:'Cx 3', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'cx4', label:'Cx 4', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'cx5', label:'Cx 5', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'residuo', label:'Resíduo', type:'number', attrs:{ step:'1', min:'0' } },
      { name:'refugo',  label:'Refugo',  type:'number', attrs:{ step:'1', min:'0' } },
    ]),
    pDescargas: bindRepeater('pDescargas','p_descargas_json',[
      { name:'tipo', label:'Tipo', type:'select', options: TIPOS_DESC },
      { name:'hhmm', label:'Tempo (HH:MM)', type:'time', attrs:{ step:'60' } },
    ]),
    pCargas: bindRepeater('pCargas','p_cargas_json',[
      { name:'tipo', label:'Tipo', type:'select', options: TIPOS_CARG },
      { name:'hhmm', label:'Tempo (HH:MM)', type:'time', attrs:{ step:'60' } },
    ]),
    fCarregamentos: bindRepeater('fCarregamentos','f_carregamentos_json',[
      { name:'tipo', label:'Tipo', type:'select', options: TIPOS_FAZ_CARG },
      { name:'hhmm', label:'Tempo (HH:MM)', type:'time', attrs:{ step:'60' } },
    ]),
    fBigBagVar: bindRepeater('fBigBagVar','f_bigbag_variedade_json',[
      { name:'variedade',   label:'Variedade', type:'select', options: VARIEDADES },
      { name:'bigbag_dia',  label:'Big bag / dia', type:'number', attrs:{ step:'1', min:'0' } },
    ]),
  };

  document.querySelectorAll('.add-row').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const key = btn.dataset.target;
      if (repeaters[key]) repeaters[key].add();
      if (key==='pRomaneio') recalcAproveitamento();
    });
  });

  document.querySelectorAll('.btn-add-desc').forEach(btn=>{
    btn.addEventListener('click', ()=>{ repeaters.pDescargas.add({ tipo: btn.dataset.tipo, hhmm:'' }); });
  });
  document.querySelectorAll('.btn-add-carg').forEach(btn=>{
    btn.addEventListener('click', ()=>{ repeaters.pCargas.add({ tipo: btn.dataset.tipo, hhmm:'' }); });
  });
  document.querySelectorAll('.btn-add-fcarg').forEach(btn=>{
    btn.addEventListener('click', ()=>{ repeaters.fCarregamentos.add({ tipo: btn.dataset.tipo, hhmm:'' }); });
  });

  (initialData.cVendas||[]).forEach(r => document.getElementById('cVendas') && repeaters.cVendas.add(r));
  (initialData.qPMBVar||[]).forEach(r => document.getElementById('qPMBVar') && repeaters.qPMBVar.add(r));
  (initialData.qBulbosVar||[]).forEach(r => document.getElementById('qBulbosVar') && repeaters.qBulbosVar.add(r));
  (initialData.pRomaneio||[]).forEach(r => document.getElementById('pRomaneio') && repeaters.pRomaneio.add(r));
  (initialData.pDescargas||[]).forEach(r => document.getElementById('pDescargas') && repeaters.pDescargas.add(r));
  (initialData.pCargas||[]).forEach(r => document.getElementById('pCargas') && repeaters.pCargas.add(r));
  (initialData.fCarregamentos||[]).forEach(r => document.getElementById('fCarregamentos') && repeaters.fCarregamentos.add(r));
  (initialData.fBigBagVar||[]).forEach(r => document.getElementById('fBigBagVar') && repeaters.fBigBagVar.add(r));

  function toNum(v){ const n = parseFloat(v); return Number.isFinite(n) ? n : 0; }
  function recalcAproveitamento(){
    if (!repeaters.pRomaneio || !document.getElementById('pRomaneio')) return;
    const rows = repeaters.pRomaneio.snap();
    const agg = {};
    for (const r of rows){
      const v = (r.variedade||'').trim();
      if (!v) continue;
      if (!agg[v]) agg[v] = {cx1:0,cx2:0,cx3:0,cx4:0,cx5:0,residuo:0,refugo:0};
      ['cx1','cx2','cx3','cx4','cx5','residuo','refugo'].forEach(k=> agg[v][k]+= toNum(r[k]));
    }
    const aprovRows = [];
    let totUti=0, totAll=0;
    Object.entries(agg).forEach(([variedade,val])=>{
      const util = val.cx1+val.cx2+val.cx3+val.cx4+val.cx5;
      const den  = util + val.residuo + val.refugo;
      const pct  = den>0 ? (util/den*100) : null;
      if (den>0){ totUti+=util; totAll+=den; }
      aprovRows.push({ variedade, aprov_pct: pct!==null? Number(pct.toFixed(2)) : '' });
    });
    if (document.getElementById('pAprovVar')) repeaters.pAprovVar.setRows(aprovRows);
    const geral = totAll>0 ? (totUti/totAll*100) : '';
    const inp = document.getElementById('p_aprov_media_input');
    if (inp) inp.value = geral!=='' ? Number(geral.toFixed(2)) : '';
  }
  const romContainer = document.getElementById('pRomaneio');
  if (romContainer){
    const obs = new MutationObserver(()=>recalcAproveitamento());
    obs.observe(romContainer, { childList:true, subtree:true });
    romContainer.addEventListener('input', ()=>recalcAproveitamento());
    recalcAproveitamento();
  }

  document.getElementById('safraForm').addEventListener('submit', ()=>{ Object.values(repeaters).forEach(rep => rep.snap && rep.snap()); });
});
</script>
</body>
</html>
