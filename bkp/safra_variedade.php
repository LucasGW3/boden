<?php
require_once __DIR__ . '/auth.php';
require_auth(); // força login
require_once __DIR__ . '/db.php';
require_once __DIR__.'/navbar.php'; // carrega wrappers e a função de render
require_once __DIR__.'/ui/datepicker.php';

/**
 * ---------- Wrappers seguros ----------
 * Evitam erros se funções do auth.php tiverem assinaturas diferentes ou não existirem.
 */

// Wrapper para chamar user_can() sem quebrar se a assinatura exigir 2+ params
if (!function_exists('user_can_safe')) {
  function user_can_safe(...$args): ?bool {
    if (!function_exists('user_can')) return null;
    try {
      $rf = new ReflectionFunction('user_can');
      $min = $rf->getNumberOfRequiredParameters();
      if (count($args) < $min) return null; // assinatura não compatível com os args passados
      return (bool) user_can(...$args);
    } catch (Throwable $e) {
      return null; // em caso de erro, não bloqueia a página
    }
  }
}

// Wrappers opcionais para capacidades específicas (se existirem em auth.php)
if (!function_exists('can_view_dashboard_var_safe')) {
  function can_view_dashboard_var_safe(): bool {
    try {
      if (function_exists('can_view_dashboard_var')) return (bool) can_view_dashboard_var();
    } catch (Throwable $e) {}
    return false;
  }
}
if (!function_exists('can_manage_users_safe')) {
  function can_manage_users_safe(): bool {
    try {
      if (function_exists('can_manage_users')) return (bool) can_manage_users();
    } catch (Throwable $e) {}
    return false;
  }
}

/**
 * ---------- Helpers de usuário/roles ----------
 * Observação: NUNCA declare user_can() aqui para não conflitar com auth.php.
 * Todas as funções abaixo são protegidas com function_exists para não redeclarar.
 */

if (!function_exists('current_user_display_name')) {
  /** Nome do usuário logado (com cache em sessão). */
  function current_user_display_name(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    // 1) cache da sessão
    $name = trim((string)($_SESSION['uname'] ?? ''));
    if ($name !== '') return $name;

    // 2) banco
    $uid = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;
    if ($uid > 0) {
      try {
        $st = pdo()->prepare("SELECT COALESCE(NULLIF(name,''), email) AS disp FROM users WHERE id = :id");
        $st->execute([':id' => $uid]);
        $val = trim((string)$st->fetchColumn());
        if ($val !== '') {
          $_SESSION['uname'] = $val;
          return $val;
        }
      } catch (Throwable $e) { /* silencioso */ }
    }

    // 3) fallback
    return trim((string)($_SESSION['uemail'] ?? ''));
  }
}

if (!function_exists('normalize_role_name')) {
  /** Normaliza uma string de role para nomes canônicos. */
  function normalize_role_name(string $r): string {
    $r0 = mb_strtolower(trim($r), 'UTF-8');

    // mapeia variações comuns para "Admin" e "Comercial"
    $aliasesAdmin = ['admin','administrator','administrador','root','superadmin','super-admin','ti_admin'];
    $aliasesCom   = ['comercial','comércio','comercio','vendas','sales','com'];

    if (in_array($r0, $aliasesAdmin, true)) return 'Admin';
    if (in_array($r0, $aliasesCom,   true)) return 'Comercial';

    // Primeira letra maiúscula (mantém consistência visual)
    return mb_convert_case($r0, MB_CASE_TITLE_SIMPLE, 'UTF-8');
  }
}

if (!function_exists('normalize_roles')) {
  /** Normaliza array de roles (remove vazios/duplicados e aplica mapeamento). */
  function normalize_roles(array $roles): array {
    $out = [];
    foreach ($roles as $r) {
      $n = normalize_role_name((string)$r);
      if ($n !== '') $out[$n] = true;
    }
    return array_keys($out);
  }
}

if (!function_exists('session_roles_guess')) {
  /**
   * Obtém roles da sessão (várias chaves comuns).
   * NÃO usa user_can() aqui para não gerar recursão.
   */
  function session_roles_guess(): array {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    $cands = [];

    // Arrays diretos
    foreach (['roles','uroles','user_roles'] as $k) {
      if (!empty($_SESSION[$k]) && is_array($_SESSION[$k])) {
        $cands = array_merge($cands, $_SESSION[$k]);
      }
    }
    // CSV/strings simples
    foreach (['roles','uroles','user_roles','role','perfil','profile','cargo'] as $k) {
      if (!empty($_SESSION[$k]) && !is_array($_SESSION[$k])) {
        $cands = array_merge($cands, array_map('trim', explode(',', (string)$_SESSION[$k])));
      }
    }
    // Flags booleanas
    foreach (['is_admin','admin','isAdmin'] as $k) {
      if (isset($_SESSION[$k]) && (int)$_SESSION[$k] === 1) $cands[] = 'Admin';
    }
    foreach (['is_comercial','comercial','isComercial','is_sales'] as $k) {
      if (isset($_SESSION[$k]) && (int)$_SESSION[$k] === 1) $cands[] = 'Comercial';
    }

    return normalize_roles($cands);
  }
}

if (!function_exists('current_user_roles')) {
  /**
   * Tenta obter roles do banco, cobrindo esquemas comuns (com try/catch em cada).
   * Faz cache em $_SESSION['uroles'].
   * Não conflita com auth.php pois o nome é idêntico porém protegido.
   */
  function current_user_roles(): array {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    // 1) já em cache?
    if (isset($_SESSION['uroles']) && is_array($_SESSION['uroles'])) {
      return normalize_roles($_SESSION['uroles']);
    }

    // 2) heurística de sessão
    $sessRoles = session_roles_guess();

    // 3) banco
    $uid = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;
    $dbRoles = [];
    if ($uid > 0) {
      // 3.1: coluna única/CSV em users (se existir)
      try {
        $st = pdo()->prepare("SELECT roles, role, is_admin, is_comercial FROM users WHERE id = :id");
        $st->execute([':id' => $uid]);
        if ($row = $st->fetch(PDO::FETCH_ASSOC)) {
          if (!empty($row['roles']))      $dbRoles = array_merge($dbRoles, array_map('trim', explode(',', (string)$row['roles'])));
          if (!empty($row['role']))       $dbRoles[] = trim((string)$row['role']);
          if (isset($row['is_admin']) && (int)$row['is_admin'] === 1)         $dbRoles[] = 'Admin';
          if (isset($row['is_comercial']) && (int)$row['is_comercial'] === 1) $dbRoles[] = 'Comercial';
        }
      } catch (Throwable $e) { /* ignora */ }

      // 3.2: user_roles + roles (JOIN clássico do seu .sql)
      if (!$dbRoles) {
        try {
          $st = pdo()->prepare("
            SELECT r.name AS role_name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = :id
          ");
          $st->execute([':id' => $uid]);
          while ($r = $st->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($r['role_name'])) $dbRoles[] = $r['role_name'];
          }
        } catch (Throwable $e) { /* ignora */ }
      }

      // 3.3: user_roles com coluna direta role_name
      if (!$dbRoles) {
        try {
          $st = pdo()->prepare("SELECT role_name FROM user_roles WHERE user_id = :id");
          $st->execute([':id' => $uid]);
          while ($r = $st->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($r['role_name'])) $dbRoles[] = $r['role_name'];
          }
        } catch (Throwable $e) { /* ignora */ }
      }

      // 3.4: user_roles com coluna 'role'
      if (!$dbRoles) {
        try {
          $st = pdo()->prepare("SELECT role FROM user_roles WHERE user_id = :id");
          $st->execute([':id' => $uid]);
          while ($r = $st->fetch(PDO::FETCH_ASSOC)) {
            if (!empty($r['role'])) $dbRoles[] = $r['role'];
          }
        } catch (Throwable $e) { /* ignora */ }
      }
    }

    // junta tudo, normaliza e cacheia
    $all = normalize_roles(array_merge($sessRoles, $dbRoles));
    $_SESSION['uroles'] = $all;
    return $all;
  }
}

if (!function_exists('user_has_role')) {
  /** Verifica se o usuário possui um papel (case-insensitive). */
  function user_has_role(string $role): bool {
    $wanted = mb_strtolower(normalize_role_name($role), 'UTF-8');
    foreach (current_user_roles() as $r) {
      if (mb_strtolower($r, 'UTF-8') === $wanted) return true;
    }
    return false;
  }
}

/**
 * Fallback extra: verifica slugs em $_SESSION['user']['roles'] hidratados no login (ex.: "comercial").
 * Útil quando não há user_can() mapeado e o papel vem só da sessão.
 */
if (!function_exists('session_has_role_slug')) {
  function session_has_role_slug(string $wanted): bool {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $wanted = mb_strtolower(trim($wanted), 'UTF-8');
    $roles = [];

    if (!empty($_SESSION['user']['roles']) && is_array($_SESSION['user']['roles'])) {
      $roles = array_map(fn($r)=>mb_strtolower((string)$r,'UTF-8'), $_SESSION['user']['roles']);
    }
    // tolera outras chaves simples:
    foreach (['role','perfil','cargo'] as $k) {
      if (!empty($_SESSION['user'][$k]) && !is_array($_SESSION['user'][$k])) {
        $parts = preg_split('/[;,|,]/', (string)$_SESSION['user'][$k]) ?: [];
        foreach ($parts as $p) $roles[] = mb_strtolower(trim($p),'UTF-8');
      }
    }
    if (!empty($_SESSION['user']['is_admin'])) $roles[] = 'admin';

    // remover acentos e espaços para melhor cobertura
    $norm = static function($txt){
      $txt = iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$txt);
      $txt = strtolower($txt);
      return preg_replace('/\s+/', '', $txt);
    };
    $wantedN = $norm($wanted);
    foreach ($roles as $r) {
      if ($norm($r) === $wantedN) return true;
    }
    return false;
  }
}

/**
 * ---------- Flags de permissão usadas no menu ----------
 * Preferimos user_can() se existir (do auth.php), para respeitar sua política.
 * Como fallback, usamos user_has_role() e slugs da sessão.
 */
$sessionResp = current_user_display_name();

// Tenta via user_can(action, resource). Se não der, cai no fallback por role/slug.
$isComercial = (user_can_safe('view', 'page_dashboard_var') ?? false)
            || (user_can_safe('access', 'comercial_area') ?? false)
            || user_has_role('Comercial')
            || session_has_role_slug('comercial');

$isAdmin     = (user_can_safe('manage', 'admin_users') ?? false)
            || (user_can_safe('admin',  'system') ?? false)
            || user_has_role('Admin')
            || session_has_role_slug('admin');



/** =======================================================================
 *  BLOQUEIO DE ACESSO À PÁGINA (somente roles: Comercial OU Admin)
 *  -----------------------------------------------------------------------
 *  Obs.: Aqui usamos SOMENTE as roles (user_has_role / session_has_role_slug)
 *  para cumprir o requisito "apenas quem é da role Comercial e Admin".
 *  As capacidades via user_can() continuam válidas para o menu, mas
 *  não destravam o acesso a esta página se a role não for adequada.
 *  ======================================================================= */
$hasRoleComercial = user_has_role('Comercial') || session_has_role_slug('comercial');
$hasRoleAdmin     = user_has_role('Admin')     || session_has_role_slug('admin');

if (!($hasRoleComercial || $hasRoleAdmin)) {
  http_response_code(403);
  header('Content-Type: text/html; charset=UTF-8');
  ?>
  <!doctype html>
  <html lang="pt-br">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Boden - Safra Cebola 25/26</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
    <link href="https://cdn.tailwindcss.com" rel="preload" as="style" onload="this.rel='stylesheet'">
    <?php render_datepicker_assets(); ?>
  </head>
  <body style="font-family: ui-sans-serif, system-ui; background:#f9fafb; color:#111827;">
    <div style="max-width:720px;margin:10vh auto;padding:24px;background:#fff;border:1px solid #e5e7eb;border-radius:12px;">
      <h1 style="font-size:20px;font-weight:700;margin:0 0 8px;">Acesso negado</h1>
      <p style="margin:0 0 16px;">Você não possui permissão para acessar esta página.</p>
      <a href="/boden/index.php" style="display:inline-block;padding:10px 14px;border-radius:9999px;background:#10b981;color:white;text-decoration:none;">Voltar</a>
    </div>
  </body>
  </html>
  <?php
  exit;
}
?>
<?php
/** ============================ FIM DO BLOQUEIO ============================ */

/** ---------- Filtros (últimos 30 dias por padrão) ----------
 * OBS: O recorte dinâmico (sem reload) será feito no front-end.
 */
$today = new DateTime('today');
$from  = isset($_GET['from']) && $_GET['from'] !== '' ? new DateTime($_GET['from']) : (clone $today)->modify('-30 days');
$to    = isset($_GET['to'])   && $_GET['to']   !== '' ? new DateTime($_GET['to'])   : $today;
$unidade = trim($_GET['unidade'] ?? '');

/** Filtro de variedades (GET var[]=... | var=csv) */
$selectedVars = [];
if (isset($_GET['var'])) {
  if (is_array($_GET['var'])) $selectedVars = array_values(array_unique(array_filter(array_map('strval', $_GET['var']))));
  else $selectedVars = array_values(array_unique(array_filter(array_map('trim', explode(',', (string)$_GET['var'])))));
}

/** ordenação dos cards: name | last | avg */
$sortParam = $_GET['sort'] ?? 'name';
$sort = in_array($sortParam, ['name','last','avg'], true) ? $sortParam : 'name';

/** ---------- Comercial: R$/kg por VARIEDADE + CAIXA ---------- */
$cStmt = pdo()->prepare("
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date BETWEEN :from AND :to
    AND (:u1 = '' OR unidade = :u2)
  ORDER BY ref_date ASC, id ASC
");
$cStmt->execute([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
]);

$comByDate = [];
$allVar = [];
$allCx  = [];

while ($row = $cStmt->fetch(PDO::FETCH_ASSOC)) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'], true) ?: [];
  $vendas = $payload['comercial']['vendas'] ?? [];
  if (!isset($comByDate[$d])) $comByDate[$d] = ['vars'=>[]];

  foreach ($vendas as $v) {
    $precoHoje   = isset($v['preco_hoje'])  && $v['preco_hoje']  !== '' ? (float)$v['preco_hoje']  : (isset($v['preco']) ? (float)$v['preco'] : null);
    $precoOntem  = isset($v['preco_ontem']) && $v['preco_ontem'] !== '' ? (float)$v['preco_ontem'] : null;
    if ($precoHoje===null && $precoOntem===null) continue;

    $kgHoje  = ($precoHoje  !== null) ? $precoHoje  / 20.0 : null;
    $kgOntem = ($precoOntem !== null) ? $precoOntem / 20.0 : null;

    $var   = trim((string)($v['variedade'] ?? ''));
    if ($var === '') $var = 'Variedade';
    $caixa = trim((string)($v['caixa'] ?? ''));
    if ($caixa === '') $caixa = 'Caixa';

    $allVar[$var] = true;
    $allCx[$caixa] = true;

    if (!isset($comByDate[$d]['vars'][$var])) {
      $comByDate[$d]['vars'][$var] = [
        'sum_atual'=>0.0,'cnt_atual'=>0,
        'sum_ant'=>0.0,'cnt_ant'=>0,
        'cx'=>[]
      ];
    }
    if ($kgHoje !== null) { $comByDate[$d]['vars'][$var]['sum_atual'] += $kgHoje;  $comByDate[$d]['vars'][$var]['cnt_atual']++; }
    if ($kgOntem!== null) { $comByDate[$d]['vars'][$var]['sum_ant']   += $kgOntem; $comByDate[$d]['vars'][$var]['cnt_ant']++; }

    if (!isset($comByDate[$d]['vars'][$var]['cx'][$caixa])) {
      $comByDate[$d]['vars'][$var]['cx'][$caixa] = ['sum_atual'=>0.0,'cnt_atual'=>0,'sum_ant'=>0.0,'cnt_ant'=>0];
    }
    if ($kgHoje !== null) {
      $comByDate[$d]['vars'][$var]['cx'][$caixa]['sum_atual'] += $kgHoje;
      $comByDate[$d]['vars'][$var]['cx'][$caixa]['cnt_atual'] += 1;
    }
    if ($kgOntem !== null) {
      $comByDate[$d]['vars'][$var]['cx'][$caixa]['sum_ant'] += $kgOntem;
      $comByDate[$d]['vars'][$var]['cx'][$caixa]['cnt_ant'] += 1;
    }
  }
}
ksort($comByDate);

/** Monta listas */
$labelsDM = [];            // 01/10
$labelsYMD = [];           // 2025-10-01
$varNames = array_keys($allVar);
sort($varNames, SORT_NATURAL | SORT_FLAG_CASE);

$cxNames  = array_keys($allCx);
sort($cxNames, SORT_NATURAL | SORT_FLAG_CASE);

/** Séries */
$seriesAtualByVarAndCx    = [];
$seriesAnteriorByVarAndCx = [];
foreach ($varNames as $vn) {
  $seriesAtualByVarAndCx[$vn]    = [];
  $seriesAnteriorByVarAndCx[$vn] = [];
  foreach ($cxNames as $cx) {
    $seriesAtualByVarAndCx[$vn][$cx]    = [];
    $seriesAnteriorByVarAndCx[$vn][$cx] = [];
  }
}
$varOverallAtual    = [];
$varOverallAnterior = [];
foreach ($varNames as $vn) { $varOverallAtual[$vn]=[]; $varOverallAnterior[$vn]=[]; }

foreach ($comByDate as $dYmd => $vals) {
  $labelsDM[]  = (new DateTime($dYmd))->format('d/m');
  $labelsYMD[] = $dYmd;
  foreach ($varNames as $vn) {
    if (isset($vals['vars'][$vn])) {
      $ag = $vals['vars'][$vn];
      $varOverallAtual[$vn][]    = ($ag['cnt_atual']>0) ? round($ag['sum_atual']/$ag['cnt_atual'], 3) : null;
      $varOverallAnterior[$vn][] = ($ag['cnt_ant']>0)   ? round($ag['sum_ant']/$ag['cnt_ant'], 3)     : null;
      foreach ($cxNames as $cx) {
        if (isset($ag['cx'][$cx])) {
          $cxAg = $ag['cx'][$cx];
          $seriesAtualByVarAndCx[$vn][$cx][]    = ($cxAg['cnt_atual']>0) ? round($cxAg['sum_atual']/$cxAg['cnt_atual'], 3) : null;
          $seriesAnteriorByVarAndCx[$vn][$cx][] = ($cxAg['cnt_ant']>0)   ? round($cxAg['sum_ant']/$cxAg['cnt_ant'], 3)     : null;
        } else {
          $seriesAtualByVarAndCx[$vn][$cx][]    = null;
          $seriesAnteriorByVarAndCx[$vn][$cx][] = null;
        }
      }
    } else {
      $varOverallAtual[$vn][]    = null;
      $varOverallAnterior[$vn][] = null;
      foreach ($cxNames as $cx) {
        $seriesAtualByVarAndCx[$vn][$cx][]    = null;
        $seriesAnteriorByVarAndCx[$vn][$cx][] = null;
      }
    }
  }
}

/** Stats (baseadas na série Atual) */
$stats = [];
foreach ($varNames as $vn) {
  $arr = $varOverallAtual[$vn] ?? [];
  $sum=0; $cnt=0; $last=null;
  foreach ($arr as $v) { if ($v!==null) { $sum+=$v; $cnt++; $last=$v; } }
  $stats[$vn] = ['last'=>$last, 'avg'=>$cnt>0 ? round($sum/$cnt,3) : null];
}

/** Ordenação inicial */
usort($varNames, function($a,$b) use($stats,$sort){
  if ($sort==='name') return strcasecmp($a,$b);
  $ka=$stats[$a][$sort]??null; $kb=$stats[$b][$sort]??null;
  $cmp = $kb <=> $ka;
  if ($cmp !== 0) return $cmp;
  return strcasecmp($a,$b);
});

/** Lista para o modal */
$allVarList = array_keys($allVar);
sort($allVarList, SORT_NATURAL | SORT_FLAG_CASE);
?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Dashboard Variedade</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: { sans: ['Nunito','ui-sans-serif','system-ui'] },
          colors: { brand: { bg:'#F4F9F2', surface:'#FFFFFF', line:'#E5F2DE', primary:'#5FB141', primaryDark:'#3C8F28', text:'#273418', muted:'#7A8F6B' } },
          borderRadius: { pill:'9999px', xl2:'1rem' },
          boxShadow: { soft:'0 6px 18px rgba(60,143,40,0.08)' }
        }
      }
    }
  </script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { background-color:#F9FAFB; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
    .card { border:1px solid rgb(229,242,222); box-shadow:0 6px 18px rgba(60,143,40,0.06); }
    .btn { transition:.2s; }
    .btn:hover { transform: translateY(-1px); }
    .mini h3 { font-size:1.05rem; }
    .mini canvas { max-height: 560px; }
    .wrap-max { max-width: 2200px; }

    /* Fullscreen: esconda tudo que tiver fs-hide */
    :fullscreen .fs-hide, :-webkit-full-screen .fs-hide { display:none !important; }
    .fs-only{ display:none; }
    :fullscreen .fs-only, :-webkit-full-screen .fs-only{ display:flex !important; }

    /* Modal */
    .modal-overlay{ position:fixed; inset:0; background:rgba(17,24,39,.45); -webkit-backdrop-filter:blur(10px); backdrop-filter:blur(10px); z-index:50; }
    .modal-card{ width:98vw; max-width:1680px; max-height:96vh; }

    .btn-lg{ padding:.95rem 1.25rem; font-size:1.05rem; border-radius:9999px; line-height:1.15; }
    .badge{ font-size:12px; line-height:1; padding:.35rem .6rem; border-radius:9999px; }

    .sel-tile{
      border:1px solid #E5F2DE; border-radius:12px;
      padding:22px; min-height:72px; display:flex; gap:16px; align-items:center;
      background:#fff; cursor:pointer; position:relative;
      transition: box-shadow .15s, border-color .15s, background .15s, transform .12s;
    }
    .sel-tile:hover{ box-shadow:0 6px 22px rgba(60,143,40,.10); transform:translateY(-1px); }
    .sel-ico{ width:38px; height:38px; display:grid; place-items:center; }
    .sel-ico svg{ width:30px; height:30px; }
    .sel-tile .check{
      position:absolute; top:12px; right:12px; width:24px; height:24px; border-radius:9999px;
      border:2px solid #CDE9BF; display:grid; place-items:center; font-size:14px; color:#5FB141; background:#fff;
      opacity:0; transform:scale(.9); transition:opacity .15s, transform .15s, border-color .15s;
    }
    .sel-tile.active{
      border-color:#5FB141; background:#F6FBF3;
      box-shadow:0 0 0 3px rgba(95,177,65,.25) inset, 0 10px 24px rgba(95,177,65,.12);
    }
    .sel-tile.active .check{ opacity:1; transform:scale(1); border-color:#5FB141; }
  </style>
  <script>
    // auto refresh 1h e Fullscreen com tecla F
    setTimeout(()=>location.reload(), 3600000);
    document.addEventListener('keydown',(e)=>{
      if (e.key.toLowerCase()==='f'){
        e.preventDefault();
        if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
        else document.exitFullscreen();
      }
    });
  </script>
  <?php render_datepicker_assets(); ?>
</head>
<body class="text-brand-text">
  <!-- NAVBAR (agora com fs-hide para sumir no fullscreen) -->
  <div class="fs-hide">
    <?php render_boden_navbar('variedade'); ?>
  </div>

  <div class="wrap-max mx-auto p-6 lg:p-10">
    <!-- MAIN -->
    <div>
      <header class="mb-6 flex items-center justify-between fs-hide">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-full flex items-center justify-center"><span class="text-3xl">🧅</span></div>
          <div>
            <h1 class="text-2xl font-bold text-brand-text">Comercial • R$/kg por Variedade</h1>
            <p id="periodoTxt" class="text-sm text-brand-muted">Período: <?php echo $from->format('d/m/Y'); ?> – <?php echo $to->format('d/m/Y'); ?></p>
          </div>
        </div>

        <!-- Botão do modal de variedades -->
        <div class="flex items-center gap-2">
          <button id="btnVars" class="btn btn-lg bg-brand-primary text-white flex items-center gap-2">
            <span>▦</span><span>Variedades</span>
            <span id="btnVarsBadge" class="badge bg-white text-brand-primary">0</span>
          </button>
        </div>
      </header>

      <!-- Filtros gerais (datas + ordem) -->
      <form id="filtersForm" class="card rounded-xl2 bg-brand-surface p-4 mb-6 fs-hide">
        <div class="grid md:grid-cols-8 gap-3 items-end">
          <div>
            <label class="text-xs text-brand-muted">De</label>
            <input id="inpFrom" type="date" value="<?php echo htmlspecialchars($from->format('Y-m-d')); ?>" class="mt-1 w-full border rounded-xl2 px-3 py-2" />
          </div>
          <div>
            <label class="text-xs text-brand-muted">Até</label>
            <input id="inpTo" type="date" value="<?php echo htmlspecialchars($to->format('Y-m-d')); ?>" class="mt-1 w-full border rounded-xl2 px-3 py-2" />
          </div>

          <div>
            <label class="text-xs text-brand-muted">Ordenar</label>
            <select id="selSort" class="mt-1 w-full border rounded-xl2 px-3 py-2">
              <option value="name" <?php echo $sort==='name'?'selected':''; ?>>Nome</option>
              <option value="last" <?php echo $sort==='last'?'selected':''; ?>>Último valor (Atual)</option>
              <option value="avg"  <?php echo $sort==='avg' ?'selected':'';   ?>>Média do período (Atual)</option>
            </select>
          </div>

          <div class="flex items-end gap-2">
            <button id="btnApplyFilters" type="button" class="px-4 py-2 rounded-pill bg-brand-primary text-white font-semibold hover:bg-brand-primaryDark">Aplicar</button>
            <div class="text-xs text-brand-muted">Dica: F = Tela Cheia • Atualiza 1h</div>
          </div>
        </div>
      </form>

      <div id="gridVar" class="grid grid-cols-1 gap-8"></div>

    <footer class="mt-12 pt-8 border-t border-brand-line text-center">
      <p class="text-sm text-brand-muted">Powered by TI - Grupo W3 © <?php echo date('Y'); ?></p>
    </footer>

      <div id="noData" class="hidden text-center text-brand-muted py-10">
        <div class="text-2xl mb-2">🤷‍♂️</div>
        <div>Nenhum dado para o período selecionado.</div>
      </div>
    </div>
  </div>

  <!-- Botão flutuante (só no Fullscreen) -->
  <div class="fs-only fixed bottom-5 right-5 z-50">
    <button id="btnVarsFS" class="btn btn-lg shadow-soft bg-brand-primary text-white flex items-center gap-2 rounded-pill">
      <span>▦</span><span>Variedades</span>
      <span id="btnVarsBadgeFS" class="badge bg-white text-brand-primary">0</span>
    </button>
  </div>

  <!-- MODAL DE VARIEDADES -->
  <div id="varsModal" class="hidden" role="dialog" aria-modal="true" aria-labelledby="varsModalTitle">
    <div class="modal-overlay"></div>
    <div class="fixed inset-0 flex items-center justify-center z-50 p-3 sm:p-6">
      <div class="modal-card card rounded-xl2 bg-brand-surface p-5 relative overflow-hidden">
        <button id="varsModalClose" class="absolute right-3 top-3 text-brand-muted hover:text-brand-text text-lg" aria-label="Fechar">✕</button>
        <div class="flex items-center justify-between mb-1">
          <h3 id="varsModalTitle" class="text-lg font-semibold">Selecionar Variedades</h3>
          <span id="varsModalCount" class="text-xs text-brand-muted" aria-live="polite">0 selecionadas</span>
        </div>

        <!-- período dentro do modal (com campos de data) -->
        <div class="grid grid-cols-1 sm:grid-cols-5 gap-2 mb-3">
          <div class="sm:col-span-2">
            <label class="text-xs text-brand-muted">De</label>
            <input id="varsModalFrom" type="date" class="mt-1 w-full border rounded-xl2 px-3 py-2" />
          </div>
          <div class="sm:col-span-2">
            <label class="text-xs text-brand-muted">Até</label>
            <input id="varsModalTo" type="date" class="mt-1 w-full border rounded-xl2 px-3 py-2" />
          </div>
          <div class="sm:col-span-1 flex items-end">
            <div class="text-xs text-brand-muted" id="varsModalPeriod">Período: —</div>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2 mb-3">
          <input id="varsModalSearch" type="text" placeholder="Buscar..." class="border rounded-xl2 px-3 py-2 text-sm flex-1 min-w-[220px]" />
          <button id="varsModalSelAll" class="btn btn-lg border text-sm" type="button">Selecionar todos</button>
          <button id="varsModalClear" class="btn btn-lg border text-sm" type="button">Limpar</button>
        </div>

        <div id="varsModalGrid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5 gap-3 max-h-[84vh] overflow-auto pr-1">
          <!-- tiles via JS -->
        </div>

        <div class="mt-4 flex justify-end gap-2">
          <button id="varsModalCancel" class="btn btn-lg border" type="button">Cancelar</button>
          <button id="varsModalApply" class="btn btn-lg bg-brand-primary text-white" type="button">Aplicar</button>
        </div>
      </div>
    </div>
  </div>

<script>
(() => {
  // ======= Config/Util =======
  console.debug('[variedades] script carregado');
  const THEME = { text:'#1e1e1e' };
  const labelsDM     = <?php echo json_encode($labelsDM, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;   // exibição
  const labelsYMD    = <?php echo json_encode($labelsYMD, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;  // filtro
  const varNamesAll  = <?php echo json_encode(array_values($varNames), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const allVarList   = <?php echo json_encode(array_values($allVarList), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const cxNames      = <?php echo json_encode(array_values($cxNames), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const S_AT         = <?php echo json_encode($seriesAtualByVarAndCx, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const S_AN         = <?php echo json_encode($seriesAnteriorByVarAndCx, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const OVER_AT      = <?php echo json_encode($varOverallAtual, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const OVER_AN      = <?php echo json_encode($varOverallAnterior, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const preSelectedVars = <?php echo json_encode(array_values($selectedVars), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  const hexToRgba = (hex, a=1) => {
    const h = hex.replace('#',''); const bigint = parseInt(h,16);
    const r = (h.length===3) ? ((bigint>>8)&0xF)*17 : (bigint>>16)&255;
    const g = (h.length===3) ? ((bigint>>4)&0xF)*17 : (bigint>>8)&255;
    const b = (h.length===3) ? (bigint&0xF)*17 : (bigint)&255;
    return `rgba(${r},${g},${b},${a})`;
  };

  Chart.defaults.color = THEME.text;
  Chart.defaults.borderColor = hexToRgba('#000', .08);
  Chart.defaults.elements.line.borderWidth = 2;

  const shortCx = (full) => {
    const m = String(full).match(/(\d+)/);
    if (!m) return full;
    const n = parseInt(m[1], 10);
    return String(n).padStart(2, '0');
  };

  // plugin p/ rotular o fim das linhas
  const endLabelPlugin = {
    id: 'endLabelPlugin',
    afterDatasetsDraw(chart) {
      const { ctx, chartArea:{ top, bottom } } = chart;
      ctx.save(); ctx.beginPath(); ctx.rect(0,0,chart.width,chart.height); ctx.clip();
      chart.data.datasets.forEach((ds, di) => {
        if (!ds.endLabel) return;
        const meta = chart.getDatasetMeta(di);
        const dataArr = ds.data || [];
        let lastIdx = -1; for (let i=dataArr.length-1;i>=0;i--){ if (dataArr[i]!=null){ lastIdx=i; break; } }
        if (lastIdx === -1) return;
        const elem = meta.data[lastIdx]; if (!elem) return;
        const { x, y } = elem.getProps(['x','y'], true);
        const text = ds.endLabelText ?? ds.label ?? '';
        ctx.font = '12px Nunito, sans-serif';
        const w = ctx.measureText(text).width;
        const tx = Math.min(x+8, chart.width - w - 6);
        const ty = Math.min(Math.max(y, top+10), bottom-10);
        ctx.fillStyle = ds.borderColor || '#333';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, tx, ty);
      });
      ctx.restore();
    }
  };

  // ======== (1) & (3) Melhorias: animações + pulsar último ponto ========
  const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const baseOpts = {
    responsive:true,
    maintainAspectRatio:false,
    layout:{ padding:{ top:8, right:30 } },
    animation: {
      duration: prefersReducedMotion ? 0 : 700,
      easing: 'easeOutCubic'
    },
    animations: {
      x: { type: 'number', duration: prefersReducedMotion ? 0 : 500, easing: 'easeOutCubic' },
      y: { type: 'number', duration: prefersReducedMotion ? 0 : 700, easing: 'easeOutCubic' }
    },
    transitions: {
      show: { animations: { x: { from: NaN }, y: { from: NaN, duration: prefersReducedMotion ? 0 : 400 } } },
      hide: { animations: { y: { to: NaN, duration: prefersReducedMotion ? 0 : 300 } } }
    },
    plugins:{
      legend:{ display:true, position:'bottom', labels:{ boxWidth:12 } },
      tooltip:{ callbacks:{ label:(ctx)=> `${ctx.dataset.label}: R$ ${(ctx.parsed.y ?? 0).toLocaleString('pt-BR',{minimumFractionDigits:2, maximumFractionDigits:3})}` } }
    },
    scales:{
      x:{ ticks:{ color: hexToRgba(THEME.text,.7) } },
      y:{ beginAtZero:true, ticks:{ color: hexToRgba(THEME.text,.7) }, title:{display:true, text:'R$/kg'} }
    }
  };

  const cxPalette = ['#0072B2','#E69F00','#D55E00','#CC79A7','#56B4E9','#000000','#009E73','#F0E442'];
  const colorForCx = (name) => cxPalette[Math.max(0, cxNames.indexOf(name)) % cxPalette.length];

  // ======= Estado/DOM =======
  let selected = new Set(preSelectedVars.length ? preSelectedVars : varNamesAll);

  // Índices ativos (recorte por data)
  let idxStart = 0;
  let idxEnd   = Math.max(0, labelsYMD.length - 1);

  // Elementos (DECLARADOS UMA ÚNICA VEZ)
  const varsModal = document.getElementById('varsModal');
  const btnVars   = document.getElementById('btnVars');
  const btnVarsFS = document.getElementById('btnVarsFS');
  const varsModalClose = document.getElementById('varsModalClose');
  const varsModalCancel= document.getElementById('varsModalCancel');
  const varsModalApply = document.getElementById('varsModalApply');
  const varsModalSelAll= document.getElementById('varsModalSelAll');
  const varsModalClear = document.getElementById('varsModalClear');
  const varsModalSearch= document.getElementById('varsModalSearch');
  const varsModalGrid  = document.getElementById('varsModalGrid');
  const varsModalCount = document.getElementById('varsModalCount');
  const varsModalPeriod= document.getElementById('varsModalPeriod');
  const varsModalFrom  = document.getElementById('varsModalFrom');
  const varsModalTo    = document.getElementById('varsModalTo');

  const filtersForm = document.getElementById('filtersForm');
  const inpFrom = document.getElementById('inpFrom');
  const inpTo   = document.getElementById('inpTo');
  const selSort = document.getElementById('selSort');
  const btnApplyFilters = document.getElementById('btnApplyFilters');
  const periodoTxt = document.getElementById('periodoTxt');

  const grid = document.getElementById('gridVar');
  const noData = document.getElementById('noData');

  const chartsAtualByVar  = new Map();
  const chartsAntByVar    = new Map();
  const chartsResumoByVar = new Map();
  const cardsByVar        = new Map();

  const mkChart = (canvas) => new Chart(canvas,{ type:'line', data:{ labels:[], datasets:[] }, options:baseOpts, plugins:[endLabelPlugin] });

  const PE_COLHEITA = 1.20;
  const PE_BENEFICIADO = 1.65;

  // ===== Helpers =====
  const sliceArr = (arr) => arr.slice(idxStart, idxEnd+1);

  // “Pulsar” o último ponto + props do dataset
  const mkLine = (label, data, color, extras={}) => {
    const lastIdx = (() => {
      let li = -1;
      for (let i = data.length - 1; i >= 0; i--) { if (data[i] != null) { li = i; break; } }
      return li;
    })();
    return {
      type:'line', label, data,
      tension:.35, fill:false, spanGaps:true,
      borderColor: color, backgroundColor: hexToRgba(color,.18),
      borderWidth: extras.borderWidth ?? 2.5,
      pointRadius: (ctx) => (ctx.dataIndex === lastIdx ? 4 : (extras.pointRadius ?? 2)),
      pointHoverRadius: (ctx) => (ctx.dataIndex === lastIdx ? 6 : (extras.pointHoverRadius ?? 4)),
      borderDash: extras.borderDash ?? [],
      endLabel: extras.endLabel ?? false,
      endLabelText: extras.endLabelText ?? null,
    };
  };

  function datasetsFor(varName, mode){
    const byCxFull = mode==='atual' ? (S_AT?.[varName]||{}) : (S_AN?.[varName]||{});
    const overFull = mode==='atual' ? (OVER_AT?.[varName]||[]) : (OVER_AN?.[varName]||[]);
    const over = sliceArr(overFull);

    const ds = (cxNames||[]).map(cx =>
      mkLine(cx, sliceArr((byCxFull?.[cx]||[])), colorForCx(cx), { endLabel:true, endLabelText: shortCx(cx) })
    );

    let s=0,c=0; for (const v of over){ if (v!=null){ s+=v; c++; } }
    if (c>0){
      const avg = Number((s/c).toFixed(3));
      ds.push(mkLine('Média do período', new Array(over.length).fill(avg), '#63AA35', {
        pointRadius:0, borderWidth:3, endLabel:true, endLabelText:'PM'
      }));
    }

    ds.push(mkLine(`PE/Colheita (${PE_COLHEITA.toFixed(2)})`, new Array(over.length).fill(PE_COLHEITA), '#F0E442', {
      borderDash:[4,4], pointRadius:0, borderWidth:2.5, endLabel:true, endLabelText:'PEC'
    }));
    ds.push(mkLine(`PE/Beneficiado (${PE_BENEFICIADO.toFixed(2)})`, new Array(over.length).fill(PE_BENEFICIADO), '#999999', {
      borderDash:[6,4], pointRadius:0, borderWidth:2.5, endLabel:true, endLabelText:'PEB'
    }));

    return ds;
  }

  function cumulativeAverage(arr){
    let s=0,c=0;
    return arr.map(v=>{
      if (v!=null){ s+=v; c++; }
      return c? Number((s/c).toFixed(3)) : null;
    });
  }

  function datasetsResumo(varName){
    const atualArr = sliceArr(OVER_AT?.[varName]||[]);
    const antArr   = sliceArr(OVER_AN?.[varName]||[]);
    const acumArr  = cumulativeAverage(atualArr);

    return [
      mkLine('Preço atual do dia', atualArr, '#0072B2', { endLabel:true, endLabelText:'AT', borderWidth:3 }),
      mkLine('Preço médio acumulado (geral)', acumArr, '#63AA35', { endLabel:true, endLabelText:'AC', borderWidth:3 }),
      mkLine('Preço médio realizado – dia anterior', antArr, '#E69F00', { endLabel:true, endLabelText:'AN', borderDash:[6,4] }),
      mkLine(`PE/Colheita (${PE_COLHEITA.toFixed(2)})`, new Array(atualArr.length).fill(PE_COLHEITA), '#F0E442', {
        borderDash:[4,4], pointRadius:0, borderWidth:2.5, endLabel:true, endLabelText:'PEC'
      }),
      mkLine(`PE/Beneficiado (${PE_BENEFICIADO.toFixed(2)})`, new Array(atualArr.length).fill(PE_BENEFICIADO), '#999999', {
        borderDash:[6,4], pointRadius:0, borderWidth:2.5, endLabel:true, endLabelText:'PEB'
      })
    ];
  }

  function buildChartsFor(varName){
    const c1 = chartsAtualByVar.get(varName);
    const c2 = chartsAntByVar.get(varName);
    const c3 = chartsResumoByVar.get(varName);
    const L  = sliceArr(labelsDM);

    if (c1){ c1.data.labels = L; c1.data.datasets = datasetsFor(varName,'atual');     c1.update(); }
    if (c2){ c2.data.labels = L; c2.data.datasets = datasetsFor(varName,'anterior');  c2.update(); }
    if (c3){ c3.data.labels = L; c3.data.datasets = datasetsResumo(varName);          c3.update(); }
  }

  function createCard(name){
    const card = document.createElement('section');
    card.className='mini card rounded-xl2 bg-brand-surface p-5 flex flex-col';
    card.dataset.variedade = name;

    const header=document.createElement('div');
    header.className='flex items-baseline justify-between mb-4';
    const h3=document.createElement('h3'); h3.className='font-semibold'; h3.textContent=name;
    const meta=document.createElement('div'); meta.className='text-xs text-brand-muted';
    meta.dataset.meta = 'avg'; // marcador
    header.appendChild(h3); header.appendChild(meta);
    card.appendChild(header);

    const gridCharts = document.createElement('div');
    gridCharts.className = 'grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch';

    const colAtual = document.createElement('div');
    const titleAtual=document.createElement('div');
    titleAtual.className='text-xs font-semibold text-brand-muted mb-1';
    titleAtual.textContent='Preço Atual';
    const canvasAtual=document.createElement('canvas');
    canvasAtual.height=480;
    colAtual.appendChild(titleAtual);
    colAtual.appendChild(canvasAtual);

    const colAnt = document.createElement('div');
    const titleAnt=document.createElement('div');
    titleAnt.className='text-xs font-semibold text-brand-muted mb-1';
    titleAnt.textContent='Preço Anterior';
    const canvasAnt=document.createElement('canvas');
    canvasAnt.height=480;
    colAnt.appendChild(titleAnt);
    colAnt.appendChild(canvasAnt);

    gridCharts.appendChild(colAtual);
    gridCharts.appendChild(colAnt);
    card.appendChild(gridCharts);

    const wrapResumo = document.createElement('div');
    wrapResumo.className='mt-4';
    const titleResumo=document.createElement('div');
    titleResumo.className='text-xs font-semibold text-brand-muted mb-1';
    titleResumo.textContent='Resumo: PM dia anterior × PM acumulado × Preço atual';
    const canvasResumo=document.createElement('canvas');
    canvasResumo.height=420;
    wrapResumo.appendChild(titleResumo);
    wrapResumo.appendChild(canvasResumo);
    card.appendChild(wrapResumo);

    grid.appendChild(card);
    cardsByVar.set(name, card);

    const chartAtual  = mkChart(canvasAtual);
    const chartAnt    = mkChart(canvasAnt);
    const chartResumo = mkChart(canvasResumo);
    chartsAtualByVar.set(name, chartAtual);
    chartsAntByVar.set(name, chartAnt);
    chartsResumoByVar.set(name, chartResumo);
    buildChartsFor(name);

    updateCardMeta(name);
  }

  function recalcStatsForVar(name){
    const arr = sliceArr(OVER_AT?.[name]||[]);
    let sum=0,c=0,last=null;
    for (const v of arr){ if (v!=null){ sum+=v; c++; last=v; } }
    return { last, avg: c>0 ? Number((sum/c).toFixed(3)) : null };
  }

  function updateCardMeta(name){
    const card = cardsByVar.get(name);
    if (!card) return;
    const meta = card.querySelector('[data-meta="avg"]');
    if (!meta) return;
    const st = recalcStatsForVar(name);
    meta.textContent = `• Preço Médio (período, série Atual): ${st.avg==null?'–':('R$ '+st.avg.toLocaleString('pt-BR',{minimumFractionDigits:2, maximumFractionDigits:3}))}`;
  }

  // Render inicial (ordem conforme PHP)
  for (const name of varNamesAll){ createCard(name); }

  // ===== Utilidades de período (modal) =====
  const fmtDisp = (ymd) => {
    if (!ymd) return '';
    const [y,m,d] = ymd.split('-');
    return `${d}/${m}/${y}`;
  };
  function previewDateFromModal(){
    const f = (varsModalFrom?.value || '').slice(0,10);
    const t = (varsModalTo?.value   || '').slice(0,10);
    const txt = (f && t) ? `Período: ${fmtDisp(f)} – ${fmtDisp(t)}` :
                (f && !t) ? `Período: desde ${fmtDisp(f)}` :
                (!f && t) ? `Período: até ${fmtDisp(t)}` : 'Período: —';
    if (varsModalPeriod) varsModalPeriod.textContent = txt;
  }

  // ===== Modal de variedades =====
  function openVarsModal(){
    varsModal.classList.remove('hidden');
    // Pré-preenche as datas do modal com as datas atuais do filtro global
    if (varsModalFrom) varsModalFrom.value = inpFrom?.value || '';
    if (varsModalTo)   varsModalTo.value   = inpTo?.value   || '';
    previewDateFromModal();

    varsModalSearch.value='';
    renderVarsTiles();
    setTimeout(()=>varsModalSearch.focus(),0);
  }
  function closeVarsModal(){ varsModal.classList.add('hidden'); }

  function renderVarsTiles(){
    const q = varsModalSearch.value.trim().toLowerCase();
    varsModalGrid.innerHTML = '';
    const current = new Set(selected);

    const arr = [...allVarList].sort((a,b)=>a.localeCompare(b,'pt-BR'));
    arr.filter(v=>!q || v.toLowerCase().includes(q)).forEach(v=>{
      const tile = document.createElement('button');
      tile.type='button';
      tile.className = 'sel-tile ' + (current.has(v) ? 'active' : '');
      tile.dataset.id = v;
      tile.setAttribute('aria-pressed', current.has(v) ? 'true' : 'false');

      const icoWrap = document.createElement('span');
      icoWrap.className='sel-ico';
      icoWrap.innerHTML = `<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="none" stroke="#273418" stroke-width="2"/><path d="M8 12l3 3 5-6" fill="none" stroke="#273418" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

      const title = document.createElement('div');
      title.className='text-base font-semibold';
      title.textContent=v;

      const check = document.createElement('span');
      check.className='check';
      check.textContent='✓';

      tile.appendChild(icoWrap);
      tile.appendChild(title);
      tile.appendChild(check);

      tile.addEventListener('click', ()=>{
        if (current.has(v)) current.delete(v); else current.add(v);
        const isActive = current.has(v);
        tile.classList.toggle('active', isActive);
        tile.setAttribute('aria-pressed', isActive ? 'true' : 'false');
        updateVarsCount(current);
        varsModal.dataset.tmpSelection = JSON.stringify([...current]);
      });

      varsModalGrid.appendChild(tile);
    });

    varsModal.dataset.tmpSelection = JSON.stringify([...current]);
    updateVarsCount(current);
  }

  function updateVarsCount(setObj){
    const count = (setObj instanceof Set) ? setObj.size : selected.size;
    varsModalCount.textContent = `${count} selecionadas`;
    const b1 = document.getElementById('btnVarsBadge');
    const b2 = document.getElementById('btnVarsBadgeFS');
    if (b1) b1.textContent = String(count);
    if (b2) b2.textContent = String(count);
  }

  function updatePeriodText(){
    const f = labelsYMD[idxStart] || '';
    const t = labelsYMD[idxEnd]   || '';
    const fmt = (s)=> {
      if (!s) return '';
      const [y,m,d] = s.split('-');
      return `${d}/${m}/${y}`;
    };
    const text = `Período: ${fmt(f)} – ${fmt(t)}`;
    if (periodoTxt) periodoTxt.textContent = text;
    if (varsModalPeriod) varsModalPeriod.textContent = text;
    console.debug('[variedades] período', {idxStart, idxEnd, f, t, text});
  }

  // Ações modal
  btnVars?.addEventListener('click', openVarsModal);
  btnVarsFS?.addEventListener('click', openVarsModal);
  varsModalClose?.addEventListener('click', closeVarsModal);
  varsModalCancel?.addEventListener('click', closeVarsModal);
  varsModalSearch?.addEventListener('input', renderVarsTiles);
  varsModalSelAll?.addEventListener('click', ()=>{ selected = new Set(allVarList); renderVarsTiles(); });
  varsModalClear?.addEventListener('click', ()=>{ selected = new Set(); renderVarsTiles(); });
  varsModal?.addEventListener('click', (e)=>{ if (e.target.classList.contains('modal-overlay')) closeVarsModal(); });

  // Campos de data no modal: pré-visualizam o período no texto
  const modalDateEnter = (e)=>{ if (e.key === 'Enter') { e.preventDefault(); } };
  varsModalFrom?.addEventListener('change', previewDateFromModal);
  varsModalTo  ?.addEventListener('change', previewDateFromModal);
  varsModalFrom?.addEventListener('keydown', modalDateEnter);
  varsModalTo  ?.addEventListener('keydown', modalDateEnter);

  // Aplicar (aplica variedades + período do modal)
  varsModalApply?.addEventListener('click', ()=>{
    // 1) aplica seleção de variedades
    try{
      const tmp = varsModal.dataset.tmpSelection ? new Set(JSON.parse(varsModal.dataset.tmpSelection)) : selected;
      selected = tmp;
    }catch(e){}

    // 2) sincroniza datas do modal -> filtros globais e redesenha
    if (varsModalFrom && inpFrom) inpFrom.value = (varsModalFrom.value || '').slice(0,10);
    if (varsModalTo   && inpTo)   inpTo.value   = (varsModalTo.value   || '').slice(0,10);
    applyDateFilterAndRedraw(); // já atualiza URL + gráficos + textos

    // 3) atualiza URL com variedades (var=csv) sem recarregar
    const url = new URL(location.href);
    if (selected.size===allVarList.length || selected.size===0) url.searchParams.delete('var');
    else url.searchParams.set('var', [...selected].join(','));
    history.replaceState(null,'', url.toString());

    closeVarsModal();
  });

  function syncBadgesOnly(){
    const count = selected.size;
    const b1 = document.getElementById('btnVarsBadge');
    const b2 = document.getElementById('btnVarsBadgeFS');
    if (b1) b1.textContent = String(count);
    if (b2) b2.textContent = String(count);
  }

  function applyVarFilterToCards(){
    const visible = new Set(selected);
    let anyVisible = false;
    cardsByVar.forEach((card, name)=>{
      const show = visible.has(name);
      card.style.display = show ? '' : 'none';
      if (show) anyVisible = true;
    });
    syncBadgesOnly();
    noData.classList.toggle('hidden', anyVisible);
  }

  // ===== Range por data (sem reload) =====
  function clampDateStr(s){ return (s || '').slice(0,10); }

  function computeRangeIndices(fromStr, toStr){
    if (!labelsYMD.length) return [0,-1];
    const f = clampDateStr(fromStr);
    const t = clampDateStr(toStr);
    let i0 = 0, i1 = labelsYMD.length - 1;
    if (f){
      for(let i=0;i<labelsYMD.length;i++){ if (labelsYMD[i] >= f){ i0=i; break; } }
    }
    if (t){
      for(let i=labelsYMD.length-1;i>=0;i--){ if (labelsYMD[i] <= t){ i1=i; break; } }
    }
    if (i0>i1){ i0=0; i1=labelsYMD.length-1; }
    return [i0,i1];
  }

  function redrawAll(){
    for (const name of cardsByVar.keys()){
      buildChartsFor(name);
      updateCardMeta(name);
    }
    resortCards();
  }

  function resortCards(){
    const sortMode = selSort.value || 'name';
    const items = [...cardsByVar.keys()].map(n=>{
      const st = recalcStatsForVar(n);
      const key = (sortMode==='name') ? n : (sortMode==='last' ? (st.last ?? Number.NEGATIVE_INFINITY) : (st.avg ?? Number.NEGATIVE_INFINITY));
      return [n,key];
    });
    items.sort((a,b)=>{
      if (selSort.value==='name') return a[0].localeCompare(b[0],'pt-BR');
      if (a[1]===b[1]) return a[0].localeCompare(b[0],'pt-BR');
      return (b[1] - a[1]);
    });

    const frag = document.createDocumentFragment();
    for (const [name] of items){
      frag.appendChild(cardsByVar.get(name));
    }
    grid.innerHTML = '';
    grid.appendChild(frag);
    applyVarFilterToCards();
  }

  function applyDateFilterAndRedraw(){
    const [i0,i1] = computeRangeIndices(inpFrom.value, inpTo.value);
    idxStart = i0; idxEnd = i1;

    // atualiza URL
    const url = new URL(location.href);
    if (inpFrom.value) url.searchParams.set('from', inpFrom.value); else url.searchParams.delete('from');
    if (inpTo.value)   url.searchParams.set('to',   inpTo.value);   else url.searchParams.delete('to');
    history.replaceState(null,'', url.toString());

    updatePeriodText();
    redrawAll();
  }

  // ===== Listeners filtros =====
  filtersForm?.addEventListener('submit', (e)=>{ e.preventDefault(); });
  btnApplyFilters?.addEventListener('click', applyDateFilterAndRedraw);
  inpFrom?.addEventListener('change', applyDateFilterAndRedraw);
  inpTo  ?.addEventListener('change', applyDateFilterAndRedraw);
  const handleEnter = (e)=>{ if (e.key === 'Enter') { e.preventDefault(); applyDateFilterAndRedraw(); } };
  inpFrom?.addEventListener('keydown', handleEnter);
  inpTo  ?.addEventListener('keydown', handleEnter);
  selSort?.addEventListener('change', resortCards);

  // ===== Inicialização =====
  const [initI0, initI1] = computeRangeIndices(inpFrom?.value, inpTo?.value);
  idxStart = initI0; idxEnd = initI1;
  updatePeriodText();

  for (const name of cardsByVar.keys()){
    buildChartsFor(name);
    updateCardMeta(name);
  }
  resortCards();
  applyVarFilterToCards();
  console.debug('[variedades] pronto', {idxStart, idxEnd, labelsTotal: labelsYMD.length});
})(); // IIFE
</script>
</body>
</html>
