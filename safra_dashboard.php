<?php
require_once __DIR__ . '/auth.php';
require_auth(); // força login
require_once __DIR__ . '/db.php';
require_once __DIR__.'/navbar.php'; // carrega wrappers e a função de render
require_once __DIR__.'/ui/datepicker.php';

/* =============================================================================
 * 0) COMPAT • Wrapper seguro para user_can() (assinaturas variadas)
 * ========================================================================== */
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

if (!function_exists('user_can_any')) {
  function user_can_any(array $pairs): bool {
    foreach ($pairs as $p) {
      if (!is_array($p) || count($p) < 2) continue;
      [$a, $r] = $p;
      $ok = user_can_safe((string)$a, (string)$r);
      if ($ok === true) return true;
    }
    return false;
  }
}

/* =============================================================================
 * 1) ROLES, UNIDADES E SEÇÕES PERMITIDAS
 * ========================================================================== */

function table_exists(string $table): bool {
  try {
    $st = pdo()->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :t LIMIT 1");
    $st->execute([':t' => $table]);
    return (bool)$st->fetchColumn();
  } catch (Throwable $e) {
    return false;
  }
}

function roles_normalize(string $s): string {
  $s = strtolower(trim($s));
  $s = strtr($s, [
    'á'=>'a','à'=>'a','ã'=>'a','â'=>'a','ä'=>'a',
    'é'=>'e','è'=>'e','ê'=>'e','ë'=>'e',
    'í'=>'i','ì'=>'i','î'=>'i','ï'=>'i',
    'ó'=>'o','ò'=>'o','õ'=>'o','ô'=>'o','ö'=>'o',
    'ú'=>'u','ù'=>'u','û'=>'u','ü'=>'u',
    'ç'=>'c'
  ]);
  return preg_replace('/\s+/', '', $s);
}

function get_user_roles_slugs(int $uid): array {
  try {
    $st = pdo()->prepare("
      SELECT r.slug
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = :uid
    ");
    $st->execute([':uid'=>$uid]);
    $rows = $st->fetchAll(PDO::FETCH_COLUMN) ?: [];
  } catch (Throwable $e) {
    $rows = [];
  }
  $norm = [];
  foreach ($rows as $s) {
    $s = roles_normalize((string)$s);
    if ($s !== '') $norm[$s] = true;
  }
  return array_keys($norm);
}

function current_user_display_name(): string {
  if (session_status() !== PHP_SESSION_ACTIVE) session_start();

  $name = trim((string)($_SESSION['uname'] ?? ''));
  if ($name !== '') return $name;

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
    } catch (Throwable $e) {}
  }
  return trim((string)($_SESSION['uemail'] ?? ''));
}

$sessionResp = current_user_display_name();

/**
 * Unidades permitidas pelas roles do usuário.
 */
function get_allowed_units_for_user(int $uid): ?array {
  $roles = get_user_roles_slugs($uid);
  if (in_array('admin', $roles, true)) return null;

  if (!table_exists('role_units')) return null;

  try {
    $st = pdo()->prepare("
      SELECT DISTINCT ru.unidade
        FROM user_roles ur
        JOIN role_units ru ON ru.role_id = ur.role_id
       WHERE ur.user_id = :uid
         AND COALESCE(ru.unidade,'') <> ''
    ");
    $st->execute([':uid'=>$uid]);
    $rows = $st->fetchAll(PDO::FETCH_COLUMN) ?: [];
    $rows = array_values(array_unique(array_filter(array_map('strval', $rows))));
    return $rows;
  } catch (Throwable $e) {
    return null;
  }
}

/* Mapa de seções por role
   +++ ADICIONADO: secProdAtingSafra (KPI geral) +++ */
$SECTIONS_BY_ROLE = [
  'comercial' => ['secComercial','secComercialOntem'],
  'logistica' => ['secLogistica'],
  'qualidade' => ['secQPelada','secQDefeitos','secQUniform','secQPmbVar','secQBulbosVar'],
  'producao'  => ['secProdSacos','secProdCarreg','secProdDesc','secProdParada','secProdAprov','secProdAting','secProdAtingSafra','secProdRomaneio'],
  'fazenda'   => ['secFazCarreg','secFazDesc','secFazPessoas','secFazColhedora','secPie'],
];
$ALL_SECTIONS = array_values(array_unique(array_merge(...array_values($SECTIONS_BY_ROLE))));

$CAP_BY_SECTION = [
  'secComercial'        => ['view',  'dashboard_comercial'],
  'secComercialOntem'   => ['view',  'dashboard_comercial'],
  'secLogistica'        => ['view',  'dashboard_logistica'],
  'secQPelada'          => ['view',  'dashboard_qualidade'],
  'secQDefeitos'        => ['view',  'dashboard_qualidade'],
  'secQUniform'         => ['view',  'dashboard_qualidade'],
  'secQPmbVar'          => ['view',  'dashboard_qualidade'],
  'secQBulbosVar'       => ['view',  'dashboard_qualidade'],
  'secProdSacos'        => ['view',  'dashboard_producao'],
  'secProdCarreg'       => ['view',  'dashboard_producao'],
  'secProdDesc'         => ['view',  'dashboard_producao'],
  'secProdParada'       => ['view',  'dashboard_producao'],
  'secProdAprov'        => ['view',  'dashboard_producao'],
  'secProdAting'        => ['view',  'dashboard_producao'],
  /* +++ NOVO +++ */
  'secProdAtingSafra'   => ['view',  'dashboard_producao'],
  'secProdRomaneio'     => ['view',  'dashboard_producao'],
  'secFazCarreg'        => ['view',  'dashboard_fazenda'],
  'secFazDesc'          => ['view',  'dashboard_fazenda'],
  'secFazPessoas'       => ['view',  'dashboard_fazenda'],
  'secFazColhedora'     => ['view',  'dashboard_fazenda'],
  'secPie'              => ['view',  'dashboard_fazenda'],
];

$me  = auth_user();
$uid = (int)($me['id'] ?? 0);
$userRoles = get_user_roles_slugs($uid);

/* Admin vê tudo */
if (in_array('admin', $userRoles, true)) {
  $allowedSections = $ALL_SECTIONS;
} else {
  $tmp = [];
  foreach ($userRoles as $r) {
    if (isset($SECTIONS_BY_ROLE[$r])) $tmp = array_merge($tmp, $SECTIONS_BY_ROLE[$r]);
  }
  $allowedSections = array_values(array_unique($tmp));

  foreach ($CAP_BY_SECTION as $secId => $cap) {
    [$action, $resource] = $cap;
    $grant = user_can_safe($action, $resource);
    if ($grant === true && !in_array($secId, $allowedSections, true)) $allowedSections[] = $secId;
  }

  $isAdminByCap = (user_can_safe('admin', 'system') ?? false) || (user_can_safe('manage', 'system') ?? false);
  if ($isAdminByCap) $allowedSections = $ALL_SECTIONS;
}
if (!$allowedSections) $allowedSections = [];

$IS_ADMIN = in_array('admin', $userRoles, true)
         || (user_can_safe('admin','system')  ?? false)
         || (user_can_safe('manage','system') ?? false);

$CAN_VIEW_VARIETY = $IS_ADMIN
                 || in_array('fazenda', $userRoles, true)
                 || user_can_any([
                      ['view','dashboard_variedade'],
                      ['view','page_dashboard_var'],
                      ['view','dashboard_comercial_variedade']
                    ]);

$CAN_MANAGE_USERS = $IS_ADMIN
                 || (user_can_safe('manage','users') ?? false)
                 || (user_can_safe('admin','users')  ?? false)
                 || (user_can_safe('create','user')  ?? false);

/* =============================================================================
 * 2) FILTROS (datas, unidade)
 * ========================================================================== */
$today   = new DateTime('today');
$from    = isset($_GET['from']) && $_GET['from'] !== '' ? new DateTime($_GET['from']) : (clone $today)->modify('-30 days');
$to      = isset($_GET['to'])   && $_GET['to']   !== '' ? new DateTime($_GET['to'])   : $today;
$unidade = trim($_GET['unidade'] ?? '');

if ($from > $to) { $tmp = $from; $from = $to; $to = $tmp; }

/* Unidades permitidas (null = sem restrição) */
$unitsAllowed     = get_allowed_units_for_user($uid);
$restrictUnitsSQL = '';
$paramsUnits      = [];

if (is_array($unitsAllowed)) {
  if (!empty($unitsAllowed)) {
    $ph = [];
    foreach ($unitsAllowed as $i=>$uVal) { $ph[]=":ru$i"; $paramsUnits[":ru$i"]=$uVal; }
    $restrictUnitsSQL = " AND unidade IN (".implode(',', $ph).") ";
    if ($unidade !== '' && !in_array($unidade, $unitsAllowed, true)) $unidade = '';
  } else {
    // Sem unidades atribuídas ⇒ por ora, sem restrição
    $restrictUnitsSQL = "";
  }
}

/* =============================================================================
 * 3) Seções selecionadas (via URL)
 * ========================================================================== */
$secParam = $_GET['sec'] ?? '';
$preSelectedSecs = [];
if ($secParam !== '') {
  $preSelectedSecs = array_values(array_unique(array_filter(array_map('trim', explode(',', $secParam)))));
  $preSelectedSecs = array_values(array_intersect($preSelectedSecs, $allowedSections));
}
if (!$preSelectedSecs) $preSelectedSecs = $allowedSections;

/* =============================================================================
 * 4) SQL HELPERS + 5) CONSULTA BASE
 * ========================================================================== */
$L_HHMM      = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.logistica.tempo_transporte_hhmm'))";
$P_TMD_HHMM  = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmd_hhmm'))";
$P_TMC_HHMM  = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmc_hhmm'))";

$F_TMC_HHMM  = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.tmc_fazenda_hhmm'))";
$F_CARR_HHMM = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.carregamento_hhmm'))";
$F_DESC_HHMM = "JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.descarregamento_hhmm'))";

$sql = "
  SELECT
    id, ref_date, DATE(created_at) AS created_day, payload_json,
    NULLIF(
      COALESCE(
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.logistica.tempo_transporte_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $L_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($L_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($L_HHMM, ':', -1) AS UNSIGNED)
          WHEN $L_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($L_HHMM)/60
          ELSE NULL
        END,
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.logistica.tmt_media')) AS DECIMAL(10,3))
      ),
      0
    ) AS l5,

    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.qualidade.pelada_pct.dia_anterior')) AS DECIMAL(10,3)) AS q6_dia,
    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.qualidade.defeitos_pct.dia_anterior')) AS DECIMAL(10,3)) AS q7_dia,
    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.qualidade.uniformidade_pct.dia_anterior')) AS DECIMAL(10,3)) AS q8_dia,

    NULLIF(
      COALESCE(
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmd_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $P_TMD_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($P_TMD_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($P_TMD_HHMM, ':', -1) AS UNSIGNED)
          WHEN $P_TMD_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($P_TMD_HHMM)/60
          ELSE NULL
        END,
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmd.dia_anterior')) AS DECIMAL(10,3))
      ),
      0
    ) AS p11_dia,

    NULLIF(
      COALESCE(
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmc_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $P_TMC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($P_TMC_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($P_TMC_HHMM, ':', -1) AS UNSIGNED)
          WHEN $P_TMC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($P_TMC_HHMM)/60
          ELSE NULL
        END,
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.tmc.dia_anterior')) AS DECIMAL(10,3))
      ),
      0
    ) AS p12_dia,

    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.sacos_beneficiados_dia.dia_anterior')) AS DECIMAL(10,3)) AS p15_dia,
    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.sacos_por_colaborador.dia_anterior')) AS DECIMAL(10,3)) AS p16_dia,

    /* FIX: aproveitamento estava vindo em producao.aproveitamento_var_pct */
    CAST(
      COALESCE(
        JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.aproveitamento_pct.dia_anterior')),
        JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.aproveitamento_var_pct.dia_anterior'))
      ) AS DECIMAL(10,3)
    ) AS p_aprov_dia,

    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.pessoas_dia.dia_anterior')) AS DECIMAL(10,3)) AS f17_dia,
    CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.colhedora_bigbag_dia.dia_anterior')) AS DECIMAL(10,3)) AS f19_dia,

    NULLIF(
      COALESCE(
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.carregamento_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $F_CARR_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($F_CARR_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($F_CARR_HHMM, ':', -1) AS UNSIGNED)
          WHEN $F_CARR_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($F_CARR_HHMM)/60
          ELSE NULL
        END,
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.tmc_fazenda_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $F_TMC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($F_TMC_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($F_TMC_HHMM, ':', -1) AS UNSIGNED)
          WHEN $F_TMC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($F_TMC_HHMM)/60
          ELSE NULL
        END,
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.tmc_fazenda.dia_anterior')) AS DECIMAL(10,3))
      ),
      0
    ) AS f_carr_dia,

    NULLIF(
      COALESCE(
        CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.fazenda.descarregamento_min')) AS DECIMAL(10,3)),
        CASE
          WHEN $F_DESC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}$' THEN
            CAST(SUBSTRING_INDEX($F_DESC_HHMM, ':', 1) AS UNSIGNED)*60
            + CAST(SUBSTRING_INDEX($F_DESC_HHMM, ':', -1) AS UNSIGNED)
          WHEN $F_DESC_HHMM REGEXP '^[0-9]{1,2}:[0-9]{2}:[0-9]{2}$' THEN
            TIME_TO_SEC($F_DESC_HHMM)/60
          ELSE NULL
        END
      ),
      0
    ) AS f_desc_dia

  FROM safra_entries
  WHERE ref_date >= :from AND ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR unidade = :u2)
  {$restrictUnitsSQL}
  ORDER BY ref_date ASC, id ASC
";
$stmt = pdo()->prepare($sql);
$params = array_merge([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
], $paramsUnits);
$stmt->execute($params ?: []);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

/* =============================================================================
 * 6) AGREGAÇÃO
 * ========================================================================== */
$metricsOverride = ['q6_dia','q7_dia','q8_dia','p16_dia','p_aprov_dia','f17_dia','f19_dia'];
$metricsSum      = ['p15_dia'];
$metricsAvg      = ['l5','p11_dia','p12_dia','p_parada_dia','f_carr_dia','f_desc_dia'];

$byDay = [];
function hhmm_to_min($txt){
  if ($txt===null || $txt==='') return null;
  if (preg_match('/^\d{1,2}:\d{2}$/', $txt)) { [$h,$m]=explode(':',$txt); return (int)$h*60 + (int)$m; }
  if (preg_match('/^\d{1,2}:[0-9]{2}:[0-9]{2}$/', $txt)) { [$h,$m,$s]=explode(':',$txt); return (int)$h*60 + (int)$m + (int)round(((int)$s)/60); }
  return null;
}
function any_to_min($maybe){
  if ($maybe===null || $maybe==='') return null;
  if (is_numeric($maybe)) {
    return (float)$maybe;
  }
  return hhmm_to_min($maybe);
}

function minutes_from_payload($value): ?float {
  if ($value === null) return null;

  if (is_array($value)) {
    $isList = array_keys($value) === range(0, count($value) - 1);

    if ($isList) {
      foreach ($value as $item) {
        $found = minutes_from_payload($item);
        if ($found !== null) return $found;
      }
      return null;
    }

    $priority = ['min','minutos','minuto','total','total_min','total_minutos','valor','value','dia','dia_anterior','hoje','atual','tempo','tempo_min','tempo_minutos','hhmm','tmc_min','tmc_hhmm','tmd_min','tmd_hhmm'];
    foreach ($priority as $key) {
      if (array_key_exists($key, $value)) {
        $found = minutes_from_payload($value[$key]);
        if ($found !== null) return $found;
      }
    }

    foreach ($value as $v) {
      $found = minutes_from_payload($v);
      if ($found !== null) return $found;
    }

    return null;
  }

  $num = any_to_min($value);
  if ($num === null) return null;
  if ($num < 0) return null;
  return (float)$num;
}

/* ===== Helper: converte dinheiro/numero em pt-BR para float ===== */
function parse_money_br($v): ?float {
  if ($v === null) return null;
  if (is_float($v) || is_int($v)) return (float)$v;
  if (is_string($v)) {
    $s = trim($v);
    if ($s === '') return null;
    // remove R$, espaços (inclusive NBSP), e separadores de milhar
    $s = str_replace(["R$", "r$", " "], "", $s);
    $s = str_replace(["\xc2\xa0"], "", $s); // NBSP
    $s = str_replace(["."], "", $s);        // milhar
    $s = str_replace([","], ".", $s);       // decimal
    // agora deve ser algo como 120.50 ou 120
    if (preg_match('/^-?\d+(\.\d+)?$/', $s)) return (float)$s;
    // fallback: tenta capturar primeiro padrão numérico dentro da string
    if (preg_match('/-?\d+(?:[.,]\d+)?/', $v, $m)) {
      $tmp = str_replace(["."], "", $m[0]);
      $tmp = str_replace([","], ".", $tmp);
      if (preg_match('/^-?\d+(\.\d+)?$/', $tmp)) return (float)$tmp;
    }
  }
  return null;
}

$prodCarrByType = [];
$prodDescByType = [];
$fazCarrByType  = [];

$logByType      = [];
$allTypesLog    = [];

$fazCarrRawSumPerDay = [];
$fazCarrRawCntPerDay = [];

$allTypesProd      = [];
$allTypesProdDesc  = [];
$allTypesFaz       = [];

$qPmbByVar     = [];
$qBulbosByVar  = [];
$qPmbVarSet    = [];
$qBulbosVarSet = [];

foreach ($rows as $r) {
  $d = $r['ref_date'];
  $descDay = $r['created_day'] ?? $d;
  if (!is_string($descDay) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $descDay)) $descDay = $d;
  $carrDay = $descDay; // usar data de criação/lançamento para carregamento também
  if (!isset($byDay[$d])) $byDay[$d] = ['override'=>[], 'sum'=>[], 'avg'=>[]];

  $payload = json_decode($r['payload_json'] ?? 'null', true) ?: [];
  $qualSection = is_array($payload['qualidade'] ?? null) ? $payload['qualidade'] : [];

  // ===== Qualidade: PMB por variedade
  $pmbItems = $qualSection['pmb_variedade'] ?? $qualSection['pmb_por_variedade'] ?? [];
  if (is_array($pmbItems)) {
    if (array_keys($pmbItems) !== range(0, count($pmbItems)-1)) $pmbItems = array_values($pmbItems);
    foreach ($pmbItems as $item) {
      if (!is_array($item)) continue;
      $varRaw = $item['variedade'] ?? $item['var'] ?? $item['nome'] ?? null;
      if (is_array($varRaw)) $varRaw = $varRaw['nome'] ?? $varRaw['label'] ?? reset($varRaw);
      $variedade = trim((string)$varRaw);
      if ($variedade === '') $variedade = 'Sem variedade';

      $valRaw = $item['pmb'] ?? $item['valor'] ?? $item['media'] ?? null;
      if (is_array($valRaw)) $valRaw = $valRaw['valor'] ?? reset($valRaw);
      $val = parse_money_br($valRaw);
      if ($val === null || $val <= 0) continue;

      $qPmbVarSet[$variedade] = true;
      if (!isset($qPmbByVar[$variedade][$d])) $qPmbByVar[$variedade][$d] = ['sum'=>0.0,'cnt'=>0];
      $qPmbByVar[$variedade][$d]['sum'] += (float)$val;
      $qPmbByVar[$variedade][$d]['cnt'] += 1;
    }
  }

  // ===== Qualidade: Bulbos/saco por variedade
  $bulbItems = $qualSection['bulbos_saco_variedade'] ?? $qualSection['bulbos_variedade'] ?? $qualSection['bulbos_por_variedade'] ?? [];
  if (is_array($bulbItems)) {
    if (array_keys($bulbItems) !== range(0, count($bulbItems)-1)) $bulbItems = array_values($bulbItems);
    foreach ($bulbItems as $item) {
      if (!is_array($item)) continue;
      $varRaw = $item['variedade'] ?? $item['var'] ?? $item['nome'] ?? null;
      if (is_array($varRaw)) $varRaw = $varRaw['nome'] ?? $varRaw['label'] ?? reset($varRaw);
      $variedade = trim((string)$varRaw);
      if ($variedade === '') $variedade = 'Sem variedade';

      $valRaw = $item['bulbos_saco'] ?? $item['bulbos'] ?? $item['qtd'] ?? $item['valor'] ?? null;
      if (is_array($valRaw)) $valRaw = $valRaw['valor'] ?? reset($valRaw);
      $val = parse_money_br($valRaw);
      if ($val === null || $val <= 0) continue;

      $qBulbosVarSet[$variedade] = true;
      if (!isset($qBulbosByVar[$variedade][$d])) $qBulbosByVar[$variedade][$d] = ['sum'=>0.0,'cnt'=>0];
      $qBulbosByVar[$variedade][$d]['sum'] += (float)$val;
      $qBulbosByVar[$variedade][$d]['cnt'] += 1;
    }
  }

  $prodSection = is_array($payload['producao'] ?? null) ? $payload['producao'] : [];
  $downtimeMin = null;
  if ($prodSection) {
    $candidates = [
      $prodSection['maquina_parada']          ?? null,
      $prodSection['maquina_parada_dia']      ?? null,
      $prodSection['maquina_parada_min']      ?? null,
      $prodSection['maquina_parada_hhmm']     ?? null,
      $prodSection['tempo_maquina_parada']    ?? null,
      $prodSection['tempo_maquina_parada_dia']?? null,
      $prodSection['tempo_maquina_parada_min']?? null,
      $prodSection['tempo_maquina_parada_hhmm']?? null,
    ];
    foreach ($prodSection as $key => $val) {
      if ($downtimeMin !== null) break;
      if (is_string($key) && mb_stripos($key, 'parad', 0, 'UTF-8') !== false) {
        $candidates[] = $val;
      }
    }
    foreach ($candidates as $cand) {
      $found = minutes_from_payload($cand);
      if ($found !== null) { $downtimeMin = $found; break; }
    }
  }
  $r['p_parada_dia'] = $downtimeMin;

  foreach ($metricsOverride as $m) {
    $v = $r[$m];
    if ($v === '' || $v === null || !is_numeric($v)) continue;
    $byDay[$d]['override'][$m] = (float)$v;
  }
  foreach ($metricsSum as $m) {
    $v = $r[$m];
    if ($v === '' || $v === null || !is_numeric($v)) continue;
    if (!isset($byDay[$d]['sum'][$m])) $byDay[$d]['sum'][$m] = 0.0;
    $byDay[$d]['sum'][$m] += (float)$v;
  }
  foreach ($metricsAvg as $m) {
    $v = $r[$m];
    if ($v === '' || $v === null || !is_numeric($v)) continue;
    if (!isset($byDay[$d]['avg'][$m])) $byDay[$d]['avg'][$m] = ['sum'=>0.0,'cnt'=>0];
    $byDay[$d]['avg'][$m]['sum'] += (float)$v;
    $byDay[$d]['avg'][$m]['cnt'] += 1;
  }

  // ===== Produção: CARREGAMENTO (bruto por tipo)
  $prodCandidates = [];
  if (!empty($payload['producao']['carregamento']))               $prodCandidates = $payload['producao']['carregamento'];
  elseif (!empty($payload['producao']['carregamento_veiculos']))  $prodCandidates = $payload['producao']['carregamento_veiculos'];
  elseif (!empty($payload['producao']['tmc_por_veiculo']))        $prodCandidates = $payload['producao']['tmc_por_veiculo'];
  if (is_array($prodCandidates)) {
    foreach ($prodCandidates as $it) {
      $tipo = trim((string)($it['tipo'] ?? $it['veiculo'] ?? 'Veículo'));
      if ($tipo==='') $tipo = 'Veículo';
      $min  = any_to_min($it['min'] ?? $it['tmc_min'] ?? $it['hhmm'] ?? $it['tmc_hhmm'] ?? null);
      if ($min===null || $min<=0) continue;
      $allTypesProd[$tipo] = true;
      if (!isset($prodCarrByType[$carrDay][$tipo])) $prodCarrByType[$carrDay][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $prodCarrByType[$carrDay][$tipo]['sum'] += (float)$min;
      $prodCarrByType[$carrDay][$tipo]['cnt'] += 1;
    }
  }

  // ===== Produção: DESCARREGAMENTO (bruto por tipo)
  $prodDescCandidates = [];
  if (!empty($payload['producao']['descarregamento']))                 $prodDescCandidates = $payload['producao']['descarregamento'];
  elseif (!empty($payload['producao']['descarregamento_veiculos']))    $prodDescCandidates = $payload['producao']['descarregamento_veiculos'];
  elseif (!empty($payload['producao']['tmd_por_veiculo']))             $prodDescCandidates = $payload['producao']['tmd_por_veiculo'];
  if (is_array($prodDescCandidates)) {
    foreach ($prodDescCandidates as $it) {
      $tipo = trim((string)($it['tipo'] ?? $it['veiculo'] ?? 'Veículo'));
      if ($tipo==='') $tipo = 'Veículo';
      $min  = any_to_min($it['min'] ?? $it['tmd_min'] ?? $it['hhmm'] ?? $it['tmd_hhmm'] ?? null);
      if ($min===null || $min<=0) continue;
      $allTypesProdDesc[$tipo] = true;
      if (!isset($prodDescByType[$descDay][$tipo])) $prodDescByType[$descDay][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $prodDescByType[$descDay][$tipo]['sum'] += (float)$min;
      $prodDescByType[$descDay][$tipo]['cnt'] += 1;
    }
  }

  // ===== Fazenda: CARREGAMENTO por tipo (valores brutos por tipo) + BRUTO global
  $fazCandidates = [];
  if (!empty($payload['fazenda']['carregamento']))                 $fazCandidates = $payload['fazenda']['carregamento'];
  elseif (!empty($payload['fazenda']['carregamento_veiculos']))    $fazCandidates = $payload['fazenda']['carregamento_veiculos'];
  elseif (!empty($payload['fazenda']['tmc_fazenda_por_veiculo']))  $fazCandidates = $payload['fazenda']['tmc_fazenda_por_veiculo'];
  if (is_array($fazCandidates)) {
    foreach ($fazCandidates as $it) {
      $tipo = trim((string)($it['tipo'] ?? $it['veiculo'] ?? 'Veículo'));
      if ($tipo==='') $tipo = 'Veículo';
      $min  = any_to_min($it['min'] ?? $it['tmc_min'] ?? $it['hhmm'] ?? $it['tmc_hhmm'] ?? null);
      if ($min===null || $min<=0) continue;
      $allTypesFaz[$tipo] = true;
      if (!isset($fazCarrByType[$d][$tipo])) $fazCarrByType[$d][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $fazCarrByType[$d][$tipo]['sum'] += (float)$min;
      $fazCarrByType[$d][$tipo]['cnt'] += 1;

      if (!isset($fazCarrRawSumPerDay[$d])) { $fazCarrRawSumPerDay[$d]=0.0; $fazCarrRawCntPerDay[$d]=0; }
      $fazCarrRawSumPerDay[$d] += (float)$min;
      $fazCarrRawCntPerDay[$d] += 1;
    }
  }

  // ===== Logística por tipo
  $payload = $payload ?: [];
  $logCandidates = [];
  if (!empty($payload['logistica']['transporte_multi'])) {
    $logCandidates = $payload['logistica']['transporte_multi'];
  } elseif (!empty($payload['logistica']['transporte'])) {
    $logCandidates = $payload['logistica']['transporte'];
  } elseif (!empty($payload['logistica']['transporte_veiculos'])) {
    $logCandidates = $payload['logistica']['transporte_veiculos'];
  } elseif (!empty($payload['logistica']['tempo_transporte'])) {
    $logCandidates = $payload['logistica']['tempo_transporte'];
  } elseif (!empty($payload['logistica']['tempo_transporte_veiculos'])) {
    $logCandidates = $payload['logistica']['tempo_transporte_veiculos'];
  } elseif (!empty($payload['logistica']['tmt_por_veiculo'])) {
    $logCandidates = $payload['logistica']['tmt_por_veiculo'];
  }

  if (is_array($logCandidates)) {
    $isAssoc = array_keys($logCandidates) !== range(0, count($logCandidates)-1);
    foreach ($logCandidates as $k => $it) {
      $tipoRaw = trim((string)($it['tipo'] ?? $it['veiculo'] ?? ($isAssoc ? $k : '')));
      $tipoNorm = mb_strtolower(str_replace('_',' ', $tipoRaw), 'UTF-8');

      if ($tipoNorm === 'carreta' || $tipoNorm === 'ls' || $tipoNorm === 'carreta ls') {
        $tipo = 'Carreta LS';
      } elseif ($tipoNorm === 'truck' || $tipoNorm === 'toco' || $tipoNorm === '3/4') {
        $tipo = 'Truck';
      } else {
        $tipo = ($tipoRaw !== '') ? $tipoRaw : null;
      }

      if ($tipo === null) continue;

      $min = any_to_min($it['min'] ?? $it['tmt_min'] ?? $it['hhmm'] ?? $it['tmt_hhmm'] ?? null);
      if ($min === null || $min <= 0) continue;

      $allTypesLog[$tipo] = true;
      if (!isset($logByType[$d][$tipo])) $logByType[$d][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $logByType[$d][$tipo]['sum'] += (float)$min;
      $logByType[$d][$tipo]['cnt'] += 1;
    }
  }
}

ksort($byDay);
ksort($prodCarrByType);
ksort($prodDescByType);
$labelsISO  = array_keys($byDay);
$labels     = [];
$allMetrics = array_merge($metricsAvg, $metricsSum, $metricsOverride);
$series     = array_fill_keys($allMetrics, []);
foreach ($byDay as $d => $bucket) {
  $labels[] = (new DateTime($d))->format('d/m');
  foreach ($metricsAvg as $m) {
    $series[$m][] = (isset($bucket['avg'][$m]) && $bucket['avg'][$m]['cnt']>0)
      ? round($bucket['avg'][$m]['sum'] / $bucket['avg'][$m]['cnt'], 3)
      : null;
  }
  foreach ($metricsSum as $m) {
    $series[$m][] = isset($bucket['sum'][$m]) ? round((float)$bucket['sum'][$m], 3) : null;
  }
  foreach ($metricsOverride as $m) {
    $series[$m][] = isset($bucket['override'][$m]) ? round((float)$bucket['override'][$m], 3) : null;
  }
}
$labelsProdCarrISO = array_keys($prodCarrByType);
$labelsProdCarr    = [];
foreach ($labelsProdCarrISO as $dCarr) {
  $labelsProdCarr[] = (new DateTime($dCarr))->format('d/m');
}
$labelsProdDescISO = array_keys($prodDescByType);
$labelsProdDesc    = [];
foreach ($labelsProdDescISO as $dDesc) {
  $labelsProdDesc[] = (new DateTime($dDesc))->format('d/m');
}

/* =======================
 * Atingimento da meta (%)
 * ======================= */

/* 1. Meta default (?meta_sb=123) */
$META_SACOS_DIA_DEFAULT = null;
if (isset($_GET['meta_sb']) && $_GET['meta_sb'] !== '') {
  $tmp = (float)$_GET['meta_sb'];
  $META_SACOS_DIA_DEFAULT = ($tmp > 0) ? $tmp : null;
}

/* 2. Meta por dia (variações de caminho no JSON) */
$sqlMeta = "
  SELECT
    ref_date,
    CAST(
      COALESCE(
        NULLIF(CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.meta_sacos_beneficiados_dia')) AS DECIMAL(10,3)), 0),
        NULLIF(CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.producao.meta_sacos_dia')) AS DECIMAL(10,3)), 0),
        NULLIF(CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.meta.sacos_beneficiados_dia')) AS DECIMAL(10,3)), 0),
        NULLIF(CAST(JSON_UNQUOTE(JSON_EXTRACT(payload_json,'$.meta.meta_sacos_beneficiados_dia')) AS DECIMAL(10,3)), 0)
      ) AS DECIMAL(10,3)
    ) AS meta_sb
  FROM safra_entries
  WHERE ref_date >= :from AND ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR unidade = :u2)
  {$restrictUnitsSQL}
  ORDER BY ref_date ASC, id ASC
";
$stMeta = pdo()->prepare($sqlMeta);
$stMeta->execute($params ?: []);
$metaByDay = [];
while ($rw = $stMeta->fetch(PDO::FETCH_ASSOC)) {
  $d = $rw['ref_date'];
  $v = $rw['meta_sb'];
  if ($v !== null && $v !== '' && is_numeric($v) && $v > 0) {
    $metaByDay[$d] = (float)$v; // última meta do dia prevalece
  }
}

/* 3. Série de % (diária) ++++ KPI SAFRA GERAL ++++ */
$atingPct = [];          // % por dia (só onde real>0 e meta>0)
$atingMetaMedia = null;  // média simples das % válidas
$valsForAvg = [];

$totalRealSafra = 0.0;
$totalMetaSafra = 0.0;
$diasComMeta    = 0;
$diasComDados   = 0; // meta>0 & real>0
$diasAtingidos  = 0;

$metaSeries = []; // alinhada às datas para recálculo no client

$i = 0;
foreach (array_keys($byDay) as $d) {
  $real = $series['p15_dia'][$i] ?? null; // sacos beneficiados (dia)
  $meta = $metaByDay[$d] ?? $META_SACOS_DIA_DEFAULT;
  $metaSeries[] = ($meta !== null && is_numeric($meta) && $meta > 0) ? (float)$meta : null;

  if ($meta !== null && is_numeric($meta) && (float)$meta > 0) $diasComMeta++;

  if (
    $real !== null && is_numeric($real) && (float)$real > 0 &&
    $meta !== null && is_numeric($meta) && (float)$meta > 0
  ) {
    $pct = round(((float)$real / (float)$meta) * 100, 2);
    $atingPct[] = $pct;
    $valsForAvg[] = $pct;

    $totalRealSafra += (float)$real;
    $totalMetaSafra += (float)$meta;
    $diasComDados++;
    if ($pct >= 100) $diasAtingidos++;
  } else {
    $atingPct[] = null;
  }
  $i++;
}
if ($valsForAvg) $atingMetaMedia = round(array_sum($valsForAvg) / count($valsForAvg), 2);
$atingSafraPct = ($totalMetaSafra > 0) ? round(($totalRealSafra / $totalMetaSafra) * 100, 2) : null;

/* =============================================================================
 * 7) Comercial — HOJE e ONTEM (média diária por SC)
 * ========================================================================== */
$cStmt = pdo()->prepare("
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date >= :from AND ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR unidade = :u2)
  {$restrictUnitsSQL}
  ORDER BY ref_date ASC, id ASC
");
$cParams = array_merge([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
], $paramsUnits);
$cStmt->execute($cParams ?: []);

/* mapas por dia */
$comHojeByDate  = []; // [Y-m-d] => ['sum'=>..., 'cnt'=>...]
$comOntemByDate = [];
$comHojeByBox   = []; // [Caixa][Y-m-d] => ['sum'=>..., 'cnt'=>...]
$comOntemByBox  = [];
$comBoxSet      = [];
$comVarietySet  = [];
$comHojeByVarBox = []; // [Variedade][Caixa][Y-m-d]
$comOntemByVarBox = [];

while ($row = $cStmt->fetch(PDO::FETCH_ASSOC)) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'], true) ?: [];
  $vendas  = $payload['comercial']['vendas'] ?? [];

  if (!isset($comHojeByDate[$d]))  $comHojeByDate[$d]  = ['sum'=>0.0,'cnt'=>0];
  if (!isset($comOntemByDate[$d])) $comOntemByDate[$d] = ['sum'=>0.0,'cnt'=>0];

  // normaliza $vendas (aceita array associativo ou lista)
  if (is_array($vendas) && array_keys($vendas) !== range(0, count($vendas)-1)) {
    // se vier objeto/dicionário, transforma em lista de itens
    $vendas = array_values($vendas);
  }

  if (!is_array($vendas)) continue;

  foreach ($vendas as $v) {
    if (!is_array($v)) continue;

        $caixaRaw = $v['caixa']
      ?? $v['caixa_nome']
      ?? $v['tipo_caixa']
      ?? $v['caixa_tipo']
      ?? $v['tipo']
      ?? null;
    if (is_array($caixaRaw)) {
      $caixaRaw = $caixaRaw['nome'] ?? $caixaRaw['label'] ?? null;
    }
    $caixa = trim((string)$caixaRaw);
    if ($caixa === '') $caixa = 'Caixa';
    $comBoxSet[$caixa] = true;

    $varRaw = $v['variedade']
      ?? $v['variedade_nome']
      ?? $v['var']
      ?? $v['variety']
      ?? null;
    if (is_array($varRaw)) {
      $varRaw = $varRaw['nome'] ?? $varRaw['label'] ?? reset($varRaw);
    }
    $variedade = trim((string)$varRaw);
    if ($variedade === '') $variedade = 'Sem variedade';
    $comVarietySet[$variedade] = true;

    $qtyRaw = $v['qntd_venda_kg']
      ?? $v['qntd_venda']
      ?? $v['qntd']
      ?? $v['quantidade']
      ?? $v['kg']
      ?? null;
    if (is_array($qtyRaw)) {
      $qtyRaw = $qtyRaw['valor'] ?? reset($qtyRaw);
    }
    $qty = parse_money_br($qtyRaw);
    if ($qty === null || $qty <= 0) {
      continue;
    }

    // ----- valores de HOJE (qualquer uma das chaves abaixo)
    $candidatosHoje = [
      $v['preco']        ?? null,
      $v['preco_hoje']   ?? null,
      $v['preco_sc']     ?? null,
      $v['preco_atual']  ?? null,
    ];
    foreach ($candidatosHoje as $raw) {
      $num = parse_money_br($raw);
      if ($num !== null && $num > 0) {
        $comHojeByDate[$d]['sum'] += $num * $qty;
        $comHojeByDate[$d]['cnt'] += $qty;
         if (!isset($comHojeByBox[$caixa])) $comHojeByBox[$caixa] = [];
        if (!isset($comHojeByBox[$caixa][$d])) $comHojeByBox[$caixa][$d] = ['sum' => 0.0, 'cnt' => 0];
        $comHojeByBox[$caixa][$d]['sum'] += $num * $qty;
        $comHojeByBox[$caixa][$d]['cnt'] += $qty;

        if (!isset($comHojeByVarBox[$variedade])) $comHojeByVarBox[$variedade] = [];
        if (!isset($comHojeByVarBox[$variedade][$caixa])) $comHojeByVarBox[$variedade][$caixa] = [];
        if (!isset($comHojeByVarBox[$variedade][$caixa][$d])) $comHojeByVarBox[$variedade][$caixa][$d] = ['sum' => 0.0, 'cnt' => 0];
        $comHojeByVarBox[$variedade][$caixa][$d]['sum'] += $num * $qty;
        $comHojeByVarBox[$variedade][$caixa][$d]['cnt'] += $qty;

        break; // considera uma por item
      }
    }

    // ----- valores de ONTEM (qualquer uma das chaves abaixo)
    $candidatosOntem = [
      $v['preco_ontem']       ?? null,
      $v['preco_realizado']   ?? null,
      $v['preco_sc_ontem']    ?? null,
    ];
    foreach ($candidatosOntem as $raw) {
      $num = parse_money_br($raw);
      if ($num !== null && $num > 0) {
        $comOntemByDate[$d]['sum'] += $num * $qty;
        $comOntemByDate[$d]['cnt'] += $qty;

        if (!isset($comOntemByBox[$caixa])) $comOntemByBox[$caixa] = [];
        if (!isset($comOntemByBox[$caixa][$d])) $comOntemByBox[$caixa][$d] = ['sum' => 0.0, 'cnt' => 0];
        $comOntemByBox[$caixa][$d]['sum'] += $num * $qty;
        $comOntemByBox[$caixa][$d]['cnt'] += $qty;

        if (!isset($comOntemByVarBox[$variedade])) $comOntemByVarBox[$variedade] = [];
        if (!isset($comOntemByVarBox[$variedade][$caixa])) $comOntemByVarBox[$variedade][$caixa] = [];
        if (!isset($comOntemByVarBox[$variedade][$caixa][$d])) $comOntemByVarBox[$variedade][$caixa][$d] = ['sum' => 0.0, 'cnt' => 0];
        $comOntemByVarBox[$variedade][$caixa][$d]['sum'] += $num * $qty;
        $comOntemByVarBox[$variedade][$caixa][$d]['cnt'] += $qty;

        break;
      }
    }
  }
}

ksort($comHojeByDate);
ksort($comOntemByDate);

// HOJE
$labelsC_H = [];
$avgPerSC_H = [];
$totalSumH = 0.0; $totalCntH = 0;
foreach ($comHojeByDate as $dateYmd => $vals) {
  $labelsC_H[] = (new DateTime($dateYmd))->format('d/m');
  $dia = ($vals['cnt']>0) ? round($vals['sum']/$vals['cnt'], 3) : null;
  $avgPerSC_H[] = $dia;
  if ($dia !== null) { $totalSumH += $dia; $totalCntH++; }
}
$mediaPeriodoSC_H = $totalCntH>0 ? round($totalSumH/$totalCntH, 3) : null;

// ONTEM
$labelsC_O = [];
$avgPerSC_O = [];
$totalSumO = 0.0; $totalCntO = 0;
foreach ($comOntemByDate as $dateYmd => $vals) {
  $labelsC_O[] = (new DateTime($dateYmd))->format('d/m');
  $dia = ($vals['cnt']>0) ? round($vals['sum']/$vals['cnt'], 3) : null;
  $avgPerSC_O[] = $dia;
  if ($dia !== null) { $totalSumO += $dia; $totalCntO++; }
}
$mediaPeriodoSC_O = $totalCntO>0 ? round($totalSumO/$totalCntO, 3) : null;

/* ISO para filtragem no client */
$labelsCISO_H = array_keys($comHojeByDate);
$labelsCISO_O = array_keys($comOntemByDate);

$comBoxNames = array_keys($comBoxSet);
natcasesort($comBoxNames);
$comBoxNames = array_values($comBoxNames);

$comVarietyNames = array_keys($comVarietySet);
natcasesort($comVarietyNames);
$comVarietyNames = array_values($comVarietyNames);

$comHojeBoxSeries = [];
$comHojeBoxCount  = [];
foreach ($comBoxNames as $boxName) {
  $boxSeries = [];
  $counts = [];
  foreach ($labelsCISO_H as $dateYmd) {
    $vals = $comHojeByBox[$boxName][$dateYmd] ?? null;
    if ($vals && $vals['cnt'] > 0) {
      $boxSeries[] = round($vals['sum'] / $vals['cnt'], 3);
      $counts[] = (float)$vals['cnt'];
    } else {
      $boxSeries[] = null;
      $counts[] = 0.0;
    }
  }
  $comHojeBoxSeries[$boxName] = $boxSeries;
  $comHojeBoxCount[$boxName]  = $counts;
}

$comOntemBoxSeries = [];
$comOntemBoxCount  = [];
foreach ($comBoxNames as $boxName) {
  $boxSeries = [];
  $counts = [];
  foreach ($labelsCISO_O as $dateYmd) {
    $vals = $comOntemByBox[$boxName][$dateYmd] ?? null;
    if ($vals && $vals['cnt'] > 0) {
      $boxSeries[] = round($vals['sum'] / $vals['cnt'], 3);
      $counts[] = (float)$vals['cnt'];
    } else {
      $boxSeries[] = null;
      $counts[] = 0.0;
    }
  }
  $comOntemBoxSeries[$boxName] = $boxSeries;
  $comOntemBoxCount[$boxName]  = $counts;
}

$comHojeVarBoxSeries = [];
$comHojeVarBoxCount  = [];
foreach ($comVarietyNames as $varName) {
  $comHojeVarBoxSeries[$varName] = [];
  $comHojeVarBoxCount[$varName]  = [];
  foreach ($comBoxNames as $boxName) {
    $boxSeries = [];
    $counts = [];
    foreach ($labelsCISO_H as $dateYmd) {
      $vals = $comHojeByVarBox[$varName][$boxName][$dateYmd] ?? null;
      if ($vals && $vals['cnt'] > 0) {
        $boxSeries[] = round($vals['sum'] / $vals['cnt'], 3);
        $counts[] = (float)$vals['cnt'];
      } else {
        $boxSeries[] = null;
        $counts[] = 0.0;
      }
    }
    $comHojeVarBoxSeries[$varName][$boxName] = $boxSeries;
    $comHojeVarBoxCount[$varName][$boxName]  = $counts;
  }
}

$comOntemVarBoxSeries = [];
$comOntemVarBoxCount  = [];
foreach ($comVarietyNames as $varName) {
  $comOntemVarBoxSeries[$varName] = [];
  $comOntemVarBoxCount[$varName]  = [];
  foreach ($comBoxNames as $boxName) {
    $boxSeries = [];
    $counts = [];
    foreach ($labelsCISO_O as $dateYmd) {
      $vals = $comOntemByVarBox[$varName][$boxName][$dateYmd] ?? null;
      if ($vals && $vals['cnt'] > 0) {
        $boxSeries[] = round($vals['sum'] / $vals['cnt'], 3);
        $counts[] = (float)$vals['cnt'];
      } else {
        $boxSeries[] = null;
        $counts[] = 0.0;
      }
    }
    $comOntemVarBoxSeries[$varName][$boxName] = $boxSeries;
    $comOntemVarBoxCount[$varName][$boxName]  = $counts;
  }
}

/* =============================================================================
  * 8) Produção — Romaneio por Variedade e Caixa
 * ========================================================================== */
$romBoxKeys = ['cx1','cx2','cx3','cx3G','cx4','cx5','diversas','residuo','refugo'];
$romBoxLabels = [
  'cx1'      => 'Cx 1',
  'cx2'      => 'Cx 2',
  'cx3'      => 'Cx 3',
  'cx3G'     => 'Cx 3G',
  'cx4'      => 'Cx 4',
  'cx5'      => 'Cx 5',
  'diversas' => 'Diversas',
  'residuo'  => 'Resíduo',
  'refugo'   => 'Refugo',
];

$sqlRom = "
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date >= :from AND ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR unidade = :u2)
  {$restrictUnitsSQL}
  ORDER BY ref_date ASC, id ASC
";
$stRom = pdo()->prepare($sqlRom);
$stRom->execute($params ?: []);

$romByDateBox = [];
$romByVarBox  = [];
$romVarietySet = [];

while ($row = $stRom->fetch(PDO::FETCH_ASSOC)) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'] ?? 'null', true) ?: [];
  $romaneio = $payload['producao']['romaneio'] ?? [];
  if (!is_array($romaneio)) continue;
  if (array_keys($romaneio) !== range(0, count($romaneio) - 1)) {
    $romaneio = array_values($romaneio);
  }

  foreach ($romaneio as $item) {
    if (!is_array($item)) continue;
    $varRaw = $item['variedade'] ?? $item['var'] ?? $item['nome'] ?? null;
    $variedade = trim((string)$varRaw);
    if ($variedade === '') $variedade = 'Sem variedade';
    $romVarietySet[$variedade] = true;

    foreach ($romBoxKeys as $boxKey) {
      if (!array_key_exists($boxKey, $item)) continue;
      $rawVal = $item[$boxKey];
      if ($rawVal === null || $rawVal === '') continue;
      if (is_array($rawVal)) {
        $rawVal = $rawVal['valor'] ?? reset($rawVal);
      }
      if (is_string($rawVal)) {
        $norm = str_replace(',', '.', preg_replace('/[^0-9,.-]/', '', $rawVal));
        $rawVal = ($norm === '' || !is_numeric($norm)) ? null : (float)$norm;
      }
      if (!is_numeric($rawVal)) continue;
      $val = (float)$rawVal;

      if (!isset($romByDateBox[$d])) $romByDateBox[$d] = [];
      if (!array_key_exists($boxKey, $romByDateBox[$d])) $romByDateBox[$d][$boxKey] = 0.0;
      $romByDateBox[$d][$boxKey] += $val;

      if (!isset($romByVarBox[$variedade])) $romByVarBox[$variedade] = [];
      if (!isset($romByVarBox[$variedade][$boxKey])) $romByVarBox[$variedade][$boxKey] = [];
      if (!array_key_exists($d, $romByVarBox[$variedade][$boxKey])) $romByVarBox[$variedade][$boxKey][$d] = 0.0;
      $romByVarBox[$variedade][$boxKey][$d] += $val;
    }
  }
}

$prodRomVarietyNames = array_keys($romVarietySet);
natcasesort($prodRomVarietyNames);
$prodRomVarietyNames = array_values($prodRomVarietyNames);

$prodRomVarBoxSeries = [];
foreach ($prodRomVarietyNames as $variedade) {
  $prodRomVarBoxSeries[$variedade] = [];
  foreach ($romBoxKeys as $boxKey) {
    $serie = [];
    foreach ($labelsISO as $d) {
      $val = $romByVarBox[$variedade][$boxKey][$d] ?? null;
      $serie[] = ($val !== null) ? round((float)$val, 3) : null;
    }
    $prodRomVarBoxSeries[$variedade][$boxKey] = $serie;
  }
}

/* =============================================================================
 * 9) F18 — Big bag por Variedade (LINHAS por dia)
 * ========================================================================== */
function payload_bigbag_var($payload) {
  return $payload['fazenda']['bigbag_por_variedade']
      ?? $payload['fazenda']['bigbag_por_variedades']
      ?? $payload['fazenda']['bigbag_variedade']
      ?? $payload['fazenda']['bigbag_variedades']
      ?? null;
}

$sqlF18 = "
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date >= :from AND ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR unidade = :u2)
  {$restrictUnitsSQL}
    AND COALESCE(
      JSON_EXTRACT(payload_json,'$.fazenda.bigbag_por_variedade'),
      JSON_EXTRACT(payload_json,'$.fazenda.bigbag_por_variedades'),
      JSON_EXTRACT(payload_json,'$.fazenda.bigbag_variedade'),
      JSON_EXTRACT(payload_json,'$.fazenda.bigbag_variedades')
    ) IS NOT NULL
  ORDER BY ref_date ASC, id ASC
";
$stF18 = pdo()->prepare($sqlF18);
$stF18->execute($params ?: []);
$f18Rows = $stF18->fetchAll(PDO::FETCH_ASSOC);

$f18ByDay = [];
$f18VarSet = [];
foreach ($f18Rows as $row) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'] ?? 'null', true) ?: [];
  $data = payload_bigbag_var($payload);
  if (!is_array($data)) continue;

  if (!isset($f18ByDay[$d])) $f18ByDay[$d] = [];
  if (array_keys($data) === range(0, count($data)-1)) {
    foreach ($data as $it) {
      $nm = trim((string)($it['variedade'] ?? $it['nome'] ?? $it['tipo'] ?? ''));
      $v  = $it['bigbag_dia'] ?? $it['qtd'] ?? $it['bigbag'] ?? $it['valor'] ?? 0;
      $v = is_numeric($v) ? (float)$v : 0.0;
      if ($nm !== '' && $v > 0) {
        $f18VarSet[$nm] = true;
        $f18ByDay[$d][$nm] = ($f18ByDay[$d][$nm] ?? 0.0) + $v;
      }
    }
  } else {
    foreach ($data as $nm => $raw) {
      $v = is_array($raw) ? ($raw['bigbag_dia'] ?? $raw['qtd'] ?? $raw['bigbag'] ?? $raw['valor'] ?? 0) : $raw;
      $v = is_numeric($v) ? (float)$v : 0.0;
      $nm = trim((string)$nm);
      if ($nm !== '' && $v > 0) {
        $f18VarSet[$nm] = true;
        $f18ByDay[$d][$nm] = ($f18ByDay[$d][$nm] ?? 0.0) + $v;
      }
    }
  }
}

ksort($f18ByDay);
$labelsISO  = array_keys($byDay);
$f18VarNames = array_keys($f18VarSet);
natcasesort($f18VarNames);
$f18VarNames = array_values($f18VarNames);

$f18SeriesByVar = [];
foreach ($f18VarNames as $vn)   $f18SeriesByVar[$vn] = [];

$f18TotalSeries = [];
foreach ($labelsISO as $d) {
  $dayMap = $f18ByDay[$d] ?? [];
  $tot = 0.0; $has = false;
  foreach ($f18VarNames as $vn) {
    $val = isset($dayMap[$vn]) ? round((float)$dayMap[$vn], 3) : null;
    $f18SeriesByVar[$vn][] = $val;
    if ($val !== null) { $tot += $val; $has = true; }
  }
  $f18TotalSeries[] = $has ? round($tot, 3) : null;
}

/* Média do período baseada na série TOTAL (ignora null/0) */
$avgOf = function($arr){
  $sum = 0; $cnt = 0;
  foreach ($arr as $v) {
    if ($v === null) continue;
    if (!is_numeric($v)) continue;
    $num = (float)$v;
    if ($num == 0.0) continue;
    $sum += $num; $cnt++;
  }
  return $cnt>0 ? round($sum/$cnt, 3) : null;
};
$f18TotalMean = $avgOf($f18TotalSeries);

/* =============================================================================
 * 10) Qualidade - PMB e Bulbos/saco por variedade
 * ========================================================================== */
$qPmbVarNames = array_keys($qPmbVarSet);
natcasesort($qPmbVarNames);
$qPmbVarNames = array_values($qPmbVarNames);

$qBulbosVarNames = array_keys($qBulbosVarSet);
natcasesort($qBulbosVarNames);
$qBulbosVarNames = array_values($qBulbosVarNames);

$qPmbSeriesByVar = [];
$qPmbCountByVar  = [];
foreach ($qPmbVarNames as $vn) {
  $serie = []; $cnts = [];
  foreach ($labelsISO as $d) {
    $vals = $qPmbByVar[$vn][$d] ?? null;
    if ($vals && $vals['cnt'] > 0) {
      $serie[] = round($vals['sum'] / $vals['cnt'], 3);
      $cnts[] = (float)$vals['cnt'];
    } else {
      $serie[] = null;
      $cnts[] = 0.0;
    }
  }
  $qPmbSeriesByVar[$vn] = $serie;
  $qPmbCountByVar[$vn]  = $cnts;
}

$qBulbosSeriesByVar = [];
$qBulbosCountByVar  = [];
foreach ($qBulbosVarNames as $vn) {
  $serie = []; $cnts = [];
  foreach ($labelsISO as $d) {
    $vals = $qBulbosByVar[$vn][$d] ?? null;
    if ($vals && $vals['cnt'] > 0) {
      $serie[] = round($vals['sum'] / $vals['cnt'], 3);
      $cnts[] = (float)$vals['cnt'];
    } else {
      $serie[] = null;
      $cnts[] = 0.0;
    }
  }
  $qBulbosSeriesByVar[$vn] = $serie;
  $qBulbosCountByVar[$vn]  = $cnts;
}

$allPmbVals = [];
foreach ($qPmbSeriesByVar as $serie) {
  foreach ($serie as $v) {
    if ($v !== null) $allPmbVals[] = $v;
  }
}
$qPmbMean = $avgOf($allPmbVals);

$allBulbosVals = [];
foreach ($qBulbosSeriesByVar as $serie) {
  foreach ($serie as $v) {
    if ($v !== null) $allBulbosVals[] = $v;
  }
}
$qBulbosMean = $avgOf($allBulbosVals);

/* =============================================================================
 * 11) Métricas resumo (gerais)
 * ========================================================================== */
$mediaLogLegacy   = $avgOf($series['l5']);
$mediaPelada= $avgOf($series['q6_dia']);
$mediaDefeitos=$avgOf($series['q7_dia']);
$mediaUniform =$avgOf($series['q8_dia']);
$mediaCarrLegacy  = $avgOf($series['f_carr_dia']);
$mediaDesc  = $avgOf($series['f_desc_dia']);
$mediaParada = $avgOf($series['p_parada_dia'] ?? []);
$mediaAprov = $avgOf($series['p_aprov_dia']);

ksort($fazCarrRawSumPerDay);
ksort($fazCarrRawCntPerDay);
$labelsISO  = array_keys($byDay);

$rawGlobalSum = array_sum($fazCarrRawSumPerDay);
$rawGlobalCnt = array_sum($fazCarrRawCntPerDay);
$mediaFazCarr_period = ($rawGlobalCnt>0) ? round($rawGlobalSum/$rawGlobalCnt, 3) : null;

/* =============================================================================
 * 12) Séries por tipo (produção, fazenda e logística)
 * ========================================================================== */
$typesProd = array_keys($allTypesProd); sort($typesProd, SORT_NATURAL|SORT_FLAG_CASE);
$typesProdDesc = array_keys($allTypesProdDesc); sort($typesProdDesc, SORT_NATURAL|SORT_FLAG_CASE);
$typesFaz  = array_keys($allTypesFaz ); sort($typesFaz , SORT_NATURAL|SORT_FLAG_CASE);
$typesLog = array_keys($allTypesLog);
$typesLog = array_values(array_filter($typesLog, function($t){
  $n = mb_strtolower($t, 'UTF-8');
  return !in_array($n, ['veiculo','veículos','veiculos'], true);
}));
sort($typesLog, SORT_NATURAL|SORT_FLAG_CASE);

$seriesProdCarrTipos = []; $seriesProdDescTipos = []; $seriesFazCarrTipos  = []; $seriesLogTipos = [];
foreach ($typesProd as $t)      $seriesProdCarrTipos[$t]  = [];
foreach ($typesProdDesc as $t)  $seriesProdDescTipos[$t]  = [];
foreach ($typesFaz as $t)       $seriesFazCarrTipos[$t]   = [];
foreach ($typesLog as $t)       $seriesLogTipos[$t]       = [];

$prodCarrDailyMeanSeries = [];
$prodDescDailyMeanSeries = [];
$logDailyMeanSeries      = [];

$prodCarrDailySumArr = [];
$prodCarrDailyCntArr = [];
$prodDescDailySumArr = [];
$prodDescDailyCntArr = [];
$logDailySumArr      = [];
$logDailyCntArr      = [];

$totalCarrSum = 0.0; $totalCarrCnt = 0;
$totalDescSum = 0.0; $totalDescCnt = 0;
$totalLogSum  = 0.0; $totalLogCnt  = 0;

foreach ($labelsProdCarrISO as $dCarr) {
  $dailyCarrSum = 0.0; $dailyCarrCnt = 0;
  foreach ($typesProd as $t) {
    $entry = $prodCarrByType[$dCarr][$t] ?? null;
    $cnt   = $entry['cnt'] ?? 0;
    if ($cnt > 0) {
      $sum = (float)$entry['sum'];
      $val = round($sum / $cnt, 3);
      $dailyCarrSum += $sum;
      $dailyCarrCnt += (int)$cnt;
    } else {
      $val = null;
    }
    $seriesProdCarrTipos[$t][] = $val;
  }
  if ($dailyCarrCnt > 0) {
    $prodCarrDailyMeanSeries[] = round($dailyCarrSum / $dailyCarrCnt, 3);
    $prodCarrDailySumArr[] = round($dailyCarrSum, 3);
    $prodCarrDailyCntArr[] = (int)$dailyCarrCnt;
    $totalCarrSum += $dailyCarrSum;
    $totalCarrCnt += $dailyCarrCnt;
  } else {
    $prodCarrDailyMeanSeries[] = null;
    $prodCarrDailySumArr[] = null;
    $prodCarrDailyCntArr[] = null;
  }

}

foreach (array_keys($byDay) as $d) {

  foreach ($typesFaz as $t) {
    $entry = $fazCarrByType[$d][$t] ?? null;
    $cnt   = $entry['cnt'] ?? 0;
    if ($cnt > 0) {
      $sum = (float)$entry['sum'];
      $seriesFazCarrTipos[$t][] = round($sum / $cnt, 3);
    } else {
      $seriesFazCarrTipos[$t][] = null;
    }
  }

  $dailyLogSum = 0.0; $dailyLogCnt = 0;
  foreach ($typesLog as $t) {
    $entry = $logByType[$d][$t] ?? null;
    $cnt   = $entry['cnt'] ?? 0;
    if ($cnt > 0) {
      $sum = (float)$entry['sum'];
      $val = round($sum / $cnt, 3);
      $dailyLogSum += $sum;
      $dailyLogCnt += (int)$cnt;
    } else {
      $val = null;
    }
    $seriesLogTipos[$t][] = $val;
  }
  if ($dailyLogCnt > 0) {
    $logDailyMeanSeries[] = round($dailyLogSum / $dailyLogCnt, 3);
    $logDailySumArr[] = round($dailyLogSum, 3);
    $logDailyCntArr[] = (int)$dailyLogCnt;
    $totalLogSum += $dailyLogSum;
    $totalLogCnt += $dailyLogCnt;
  } else {
    $logDailyMeanSeries[] = null;
    $logDailySumArr[] = null;
    $logDailyCntArr[] = null;
  }
}

foreach ($labelsProdDescISO as $dDesc) {
  $dailyDescSum = 0.0; $dailyDescCnt = 0;
  foreach ($typesProdDesc as $t) {
    $entry = $prodDescByType[$dDesc][$t] ?? null;
    $cnt   = $entry['cnt'] ?? 0;
    if ($cnt > 0) {
      $sum = (float)$entry['sum'];
      $val = round($sum / $cnt, 3);
      $dailyDescSum += $sum;
      $dailyDescCnt += (int)$cnt;
    } else {
      $val = null;
    }
    $seriesProdDescTipos[$t][] = $val;
  }
  if ($dailyDescCnt > 0) {
    $prodDescDailyMeanSeries[] = round($dailyDescSum / $dailyDescCnt, 3);
    $prodDescDailySumArr[] = round($dailyDescSum, 3);
    $prodDescDailyCntArr[] = (int)$dailyDescCnt;
    $totalDescSum += $dailyDescSum;
    $totalDescCnt += $dailyDescCnt;
  } else {
    $prodDescDailyMeanSeries[] = null;
    $prodDescDailySumArr[] = null;
    $prodDescDailyCntArr[] = null;
  }
}

/* Médias do período (min) */
$mediaTMC_period = ($totalCarrCnt>0) ? round($totalCarrSum/$totalCarrCnt, 3) : null;
$mediaTMD_period = ($totalDescCnt>0) ? round($totalDescSum/$totalDescCnt, 3) : null;
$mediaLog_all    = ($totalLogCnt >0) ? round($totalLogSum /$totalLogCnt , 3) : null;

/* LOGÍSTICA (2 veículos + média) */
$desiredLogTypes = ['Carreta LS', 'Truck'];
$typesLogSel = array_values(array_intersect($desiredLogTypes, $typesLog));
if (!$typesLogSel) {
  $typesLogSel = array_slice($typesLog, 0, min(2, count($typesLog)));
}

$seriesLogTiposSel = [];
foreach ($typesLogSel as $t) { $seriesLogTiposSel[$t] = $seriesLogTipos[$t] ?? []; }

$logDailyMeanSel = [];
$logDailySumSel  = [];
$logDailyCntSel  = [];
$lenLabels = count($labels);
$logSelTotalSum = 0.0; $logSelTotalCnt = 0;
for ($i=0; $i<$lenLabels; $i++) {
  $dayIso = $labelsISO[$i] ?? null;
  $sum = 0.0; $cnt = 0;
  foreach ($typesLogSel as $t) {
$entry = ($dayIso !== null) ? ($logByType[$dayIso][$t] ?? null) : null;
    $c = $entry['cnt'] ?? 0;
    if ($c > 0) {
      $sum += (float)$entry['sum'];
      $cnt += (int)$c;
    }
  }
  if ($cnt > 0) {
    $logDailySumSel[] = round($sum, 3);
    $logDailyCntSel[] = $cnt;
    $logDailyMeanSel[] = round($sum / $cnt, 3);
    $logSelTotalSum += $sum;
    $logSelTotalCnt += $cnt;
  } else {
    $logDailySumSel[] = null;
    $logDailyCntSel[] = null;
    $logDailyMeanSel[] = null;
  }
}
$mediaLogSel = ($logSelTotalCnt>0) ? round($logSelTotalSum/$logSelTotalCnt, 3) : null;

$fazCarrRawSumArr = [];
$fazCarrRawCntArr = [];
$fazCarrDailyMeanSeries = [];
foreach ($labelsISO as $d) {
  $sum = isset($fazCarrRawSumPerDay[$d]) ? (float)$fazCarrRawSumPerDay[$d] : null;
  $cnt = isset($fazCarrRawCntPerDay[$d]) ? (int)$fazCarrRawCntPerDay[$d] : 0;
  if ($cnt > 0 && $sum !== null) {
    $fazCarrRawSumArr[] = round($sum, 3);
    $fazCarrRawCntArr[] = $cnt;
    $fazCarrDailyMeanSeries[] = round($sum / $cnt, 3);
  } else {
    $fazCarrRawSumArr[] = null;
    $fazCarrRawCntArr[] = null;
    $fazCarrDailyMeanSeries[] = null;
  }
}

$labelsCISO = array_keys($comHojeByDate);

$mediaF17 = $avgOf($series['f17_dia']);
$mediaF19 = $avgOf($series['f19_dia']);

?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Dashboard Geral</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&display=swap" rel="stylesheet">
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
  <link rel="stylesheet" href="./dist/styles.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { background-color:#F9FAFB; -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale; }
    .card { border:1px solid rgb(229,242,222); box-shadow:0 6px 18px rgba(60,143,40,0.06); }
    .tv h2 { font-size:1.05rem; }
    .tv canvas { max-height: 360px; }

    .btn { transition: .2s; --px: .70rem; padding: .5rem var(--px); border-radius: 0.75rem; font-weight: 600; }
    .btn:hover { transform: translateY(-1px); }
    .btn--compact{ --px: .55rem; }
    .btn-lg{ padding:.65rem var(--px); font-size:1rem; border-radius:9999px; }
    .btn-xl{ padding:.75rem var(--px); font-size:1.0625rem; border-radius:9999px; }

    :fullscreen .fs-hide, :-webkit-full-screen .fs-hide { display:none !important; }
    :fullscreen .prod-nav, :-webkit-full-screen .prod-nav { display:none !important; }
    .fs-only{ display:none; }
    :fullscreen .fs-only, :-webkit-full-screen .fs-only{ display:flex !important; }
    .wrap-max { max-width: 2000px; }
    #gridCharts{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:1.5rem; }
    @media (max-width:420px){ #gridCharts{ grid-template-columns:1fr; } }
    .badge{ font-size:12px; line-height:1; padding:.3rem .5rem; border-radius:9999px; }

    #graphsModal{
      position:fixed;
      inset:0;
      z-index:2000;
      display:none;
      align-items:stretch;
      justify-content:stretch;
    }
    #graphsModal:not(.hidden){ display:flex; }
    .modal-overlay{
      position:absolute;
      inset:0;
      background:rgba(17,24,39,.45);
      -webkit-backdrop-filter:blur(10px);
      backdrop-filter:blur(10px);
      z-index:0;
    }
    .modal-shell{
      position:relative;
      z-index:1;
      width:100%;
      min-height:100%;
      display:flex;
      align-items:flex-start;
      justify-content:center;
      padding:1.5rem 1rem;
      overflow:auto;
    }

    /* Modais compactos (comercial) */
    .modal-backdrop{
      position:fixed;
      inset:0;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:12px;
      background:rgba(17,24,39,0.35);
      -webkit-backdrop-filter:blur(6px);
      backdrop-filter:blur(6px);
      z-index:1800;
    }
    .modal-backdrop.hidden{ display:none; }
    .modal-compact{
      width:100%;
      max-width:460px;
      background:#fff;
      border-radius:18px;
      border:1px solid rgba(0,0,0,0.05);
      box-shadow:0 12px 40px rgba(0,0,0,0.12);
      padding:18px 18px 14px;
      position:relative;
    }
    .modal-compact h3{
      margin:0;
      font-size:16px;
      font-weight:700;
      color:#1f2933;
    }
    .modal-compact .modal-head{
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:12px;
      margin-bottom:12px;
    }
    .modal-compact .close-btn{
      border:none;
      background:transparent;
      color:#6b7280;
      font-size:20px;
      line-height:1;
      cursor:pointer;
    }
    .modal-compact .close-btn:hover{ color:#111827; }
    .modal-compact .footer{
      margin-top:16px;
      display:flex;
      justify-content:flex-end;
      gap:8px;
    }
    .modal-card{
      width:min(1500px, calc(100vw - 2rem));
      max-width:1680px;
      max-height:calc(100vh - 3rem);
      overflow:auto;
    }
    @media (max-width:640px){
      .modal-shell{ padding:1rem; }
      .modal-card{ width:100%; max-height:calc(100vh - 2rem); }
    }
    .sel-tile{ border:1px solid #E5F2DE; border-radius:12px; padding:18px; display:flex; gap:14px; align-items:center; background:#fff; cursor:pointer; position:relative; transition: box-shadow .15s, border-color .15s, background .15s, transform .12s; }
    .sel-tile:hover{ box-shadow:0 6px 22px rgba(60,143,40,.10); transform:translateY(-1px); }
    .sel-ico{ width:34px; height:34px; display:grid; place-items:center; }
    .sel-ico svg{ width:28px; height:28px; }
    .sel-tile .check{ position:absolute; top:10px; right:10px; width:22px; height:22px; border-radius:9999px; border:2px solid #CDE9BF; display:grid; place-items:center; font-size:14px; color:#5FB141; background:#fff; opacity:0; transform:scale(.9); transition:opacity .15s, transform .15s, border-color .15s; }
    .sel-tile.active{ border-color:#5FB141; background:#F6FBF3; box-shadow:0 0 0 3px rgba(95,177,65,.25) inset, 0 10px 24px rgba(95,177,65,.12); }
    .sel-tile.active .check{ opacity:1; transform:scale(1); border-color:#5FB141; }
    #gridCharts canvas { width:100% !important; height:auto !important; }

    #modalGridCols{
      display: flex;
      flex-wrap: nowrap;
      gap: 10px;
      max-height: 70vh;
      overflow-y: auto;
      overflow-x: hidden;
      padding-right: .25rem;
      padding-bottom: .25rem;
      scroll-behavior: smooth;
      width: 100%;
    }

    .role-col{
      display:flex;
      flex-direction:column;
      gap:10px;
      flex: 0 0 280px;
      max-width: 280px;
    }
    @media (max-width: 1024px){
      .role-col{ flex-basis: 300px; max-width: 300px; }
    }
    @media (max-width: 640px){
      .role-col{ flex-basis: 260px; max-width: 260px; }
    }

    .role-header{ position:sticky; top:0; background:#fff; z-index:1; padding:2px 2px 6px 2px; }
    .role-title{ font-weight:700; font-size:.9rem; color:#273418; display:flex; align-items:center; gap:.5rem; }
    .role-count{ font-size:.75rem; color:#7A8F6B; }

    .btn{
      padding:.32rem .50rem !important;
      font-size:.875rem !important;
      border-radius:9999px;
      min-width: unset !important;
    }
    .btn-lg{
      padding:.48rem .70rem !important;
      font-size:.92rem !important;
    }
    .btn-xl{
      padding:.58rem .85rem !important;
      font-size:.98rem !important;
    }
    .fab-btn{ padding:.48rem .70rem !important; }

    .badge{
      font-size:10.5px;
      padding:.22rem .42rem;
    }

    .sel-tile{ padding:12px; gap:10px; }
    .sel-ico{ width:28px; height:28px; }
    .sel-ico svg{ width:22px; height:22px; }
    .sel-tile .text-base{ font-size:.95rem; }

    .actions-lg{ flex-wrap: nowrap; }
    header.flex{ flex-wrap: nowrap; }
  </style>
  <script>
    setTimeout(()=>location.reload(), 3600000); // Auto-refresh 1h
    document.addEventListener('keydown',(e)=>{
      if(e.key.toLowerCase()==='f'){
        if(!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
        else document.exitFullscreen();
      }
    });
  </script>
  <?php render_datepicker_assets(); ?>
</head>
<body class="text-brand-text tv">
  <!-- Navbar (escondida no FS via CSS) -->
  <?php render_boden_navbar('dashboard'); ?>

  <div class="wrap-max mx-auto p-6 lg:p-10">
    <!-- HEADER + FILTROS -->
    <header class="mb-4 flex items-center justify-between flex-nowrap gap-4 fs-hide overflow-x-auto">
      <div class="flex items-center gap-3 flex-nowrap min-w-0">
        <div class="w-10 h-10 rounded-full flex items-center justify-center"><span class="text-4xl">🧅</span></div>
        <h1 class="text-2xl font-bold text-brand-text whitespace-nowrap">Safra Cebola 25/26</h1>

        <div class="flex items-center gap-2">
          <button id="btnFull" title="Tela cheia (F)" class="btn btn--compact btn-lg border bg-white">⛶</button>
          <button id="btnGraphs" class="btn btn--compact btn-lg fab-btn bg-brand-primary text-white flex items-center gap-2">
            <span>▦</span><span>Gráficos</span>
            <span id="btnGraphsBadge" class="badge bg-white text-brand-primary">0</span>
          </button>
        </div>
      </div>

      <!-- Filtros de data -->
      <form method="GET" class="flex items-end gap-2 shrink-0">
        <div>
          <label class="text-xs text-brand-muted">De</label>
          <input id="headFrom" type="date" name="from" value="<?php echo htmlspecialchars($from->format('Y-m-d')); ?>" class="mt-1 border rounded-xl2 px-3 py-2" />
        </div>
        <div>
          <label class="text-xs text-brand-muted">Até</label>
          <input id="headTo" type="date" name="to" value="<?php echo htmlspecialchars($to->format('Y-m-d')); ?>" class="mt-1 border rounded-xl2 px-3 py-2" />
        </div>
        <div id="secHiddenInputs" class="hidden"></div>
        <button class="px-3 py-2 rounded-pill bg-brand-primary text-white font-semibold hover:bg-brand-primaryDark">Aplicar</button>
      </form>
    </header>

    <!-- GRID DE GRÁFICOS -->
    <div id="gridCharts">

      <?php if (in_array('secProdAtingSafra', $allowedSections, true)): ?>
      <!-- +++ NOVO: KPI GERAL SAFRA +++ -->
      <section id="secProdAtingSafra" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Safra • Atingimento Geral da Meta</h2>
        <div class="flex items-center gap-6 flex-wrap">
          <div>
            <div id="kp-ating-safra" class="text-4xl font-extrabold">—</div>
            <div id="kp-ating-desc" class="text-sm text-brand-muted">—</div>
          </div>
          <div class="relative w-24 h-24 sm:w-28 sm:h-28 md:w-32 md:h-32">
          <canvas id="chartGaugeSafra"></canvas>
        </div>
        </div>
        <div id="kp-ating-extra" class="mt-3 text-sm text-brand-muted">—</div>
      </section>
      <?php endif; ?>

      <?php if (in_array('secComercial', $allowedSections, true)): ?>
      <section id="secComercial" class="card rounded-xl2 bg-brand-surface p-5">
        <div class="flex items-start justify-between gap-2 mb-1">
          <h2 class="font-semibold">Comercial - Preco por SC - Hoje (R$)</h2>
          <button id="btnComercialHojeFilters" type="button" class="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-brand-line bg-white text-brand-text hover:bg-brand-surface-strong shadow-sm transition">
            <span aria-hidden="true" class="text-sm leading-none">&equiv;</span>
            <span class="font-semibold">Filtros</span>
          </button>
        </div>
        <p id="com-meta" class="text-xs text-brand-muted mb-3">-</p>
        <canvas id="chartComercialMedia"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secComercialOntem', $allowedSections, true)): ?>
      <section id="secComercialOntem" class="card rounded-xl2 bg-brand-surface p-5">
        <div class="flex items-start justify-between gap-2 mb-1">
          <h2 class="font-semibold">Comercial - Preco por SC - Realizado (R$)</h2>
          <button id="btnComercialOntemFilters" type="button" class="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-brand-line bg-white text-brand-text hover:bg-brand-surface-strong shadow-sm transition">
            <span aria-hidden="true" class="text-sm leading-none">&equiv;</span>
            <span class="font-semibold">Filtros</span>
          </button>
        </div>
        <p id="com-ontem-meta" class="text-xs text-brand-muted mb-3">-</p>
        <canvas id="chartComercialOntem"></canvas>
      </section>
      <?php endif; ?>


      <!-- Modais de filtro do Comercial -->
      <div id="modalComercialHoje" class="modal-backdrop hidden">
        <div class="modal-compact">
          <div class="modal-head">
            <h3>Filtros - Comercial Hoje</h3>
            <button type="button" class="close-btn" data-close-modal="1" aria-label="Fechar">&times;</button>
          </div>
          <?php if (!empty($comVarietyNames)): ?>
          <div class="mb-3">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Variedades</p>
            <div id="comercialVarietyPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <?php endif; ?>
          <div class="mb-2">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Caixas</p>
            <div id="comercialVarPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <div class="footer">
            <button type="button" class="px-3 py-1.5 text-sm rounded-lg border border-brand-line text-brand-text hover:bg-brand-surface-strong" data-close-modal="1">Fechar</button>
          </div>
        </div>
      </div>

      <div id="modalComercialOntem" class="modal-backdrop hidden">
        <div class="modal-compact">
          <div class="modal-head">
            <h3>Filtros - Comercial Realizado</h3>
            <button type="button" class="close-btn" data-close-modal="1" aria-label="Fechar">&times;</button>
          </div>
          <?php if (!empty($comVarietyNames)): ?>
          <div class="mb-3">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Variedades</p>
            <div id="comercialOntemVarietyPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <?php endif; ?>
          <div class="mb-2">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Caixas</p>
            <div id="comercialOntemVarPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <div class="footer">
            <button type="button" class="px-3 py-1.5 text-sm rounded-lg border border-brand-line text-brand-text hover:bg-brand-surface-strong" data-close-modal="1">Fechar</button>
          </div>
        </div>
      </div>
      <div id="modalQPmb" class="modal-backdrop hidden">
        <div class="modal-compact">
          <div class="modal-head">
            <h3>Filtros - PMB por variedade</h3>
            <button type="button" class="close-btn" data-close-modal="1" aria-label="Fechar">&times;</button>
          </div>
          <?php if (!empty($qPmbVarNames)): ?>
          <div class="mb-3">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Variedades</p>
            <div id="qPmbVarPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <?php else: ?>
          <p class="text-sm text-brand-muted">Sem variedades registradas para o período.</p>
          <?php endif; ?>
          <div class="footer">
            <button type="button" class="px-3 py-1.5 text-sm rounded-lg border border-brand-line text-brand-text hover:bg-brand-surface-strong" data-close-modal="1">Fechar</button>
          </div>
        </div>
      </div>

      <div id="modalQBulbos" class="modal-backdrop hidden">
        <div class="modal-compact">
          <div class="modal-head">
            <h3>Filtros - Nº Bulbos/saco por variedade</h3>
            <button type="button" class="close-btn" data-close-modal="1" aria-label="Fechar">&times;</button>
          </div>
          <?php if (!empty($qBulbosVarNames)): ?>
          <div class="mb-3">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Variedades</p>
            <div id="qBulbosVarPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <?php else: ?>
          <p class="text-sm text-brand-muted">Sem variedades registradas para o período.</p>
          <?php endif; ?>
          <div class="footer">
            <button type="button" class="px-3 py-1.5 text-sm rounded-lg border border-brand-line text-brand-text hover:bg-brand-surface-strong" data-close-modal="1">Fechar</button>
          </div>
        </div>
      </div>

      <?php if (in_array('secLogistica', $allowedSections, true)): ?>
      <section id="secLogistica" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Logística • Tempo de transporte (h)</h2>
        <p id="log-meta" class="text-xs text-brand-muted mb-3">-</p>
        <canvas id="chartLogistica"></canvas>
      </section>
      <?php endif; ?>
      <?php if (in_array('secQPelada', $allowedSections, true)): ?>
      <section id="secQPelada" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Qualidade • Cebola Pelada (%)</h2>
        <p id="q-meta-pelada" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartQPelada"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secQDefeitos', $allowedSections, true)): ?>
      <section id="secQDefeitos" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Qualidade • Defeitos (%)</h2>
        <p id="q-meta-defeitos" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartQDefeitos"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secQUniform', $allowedSections, true)): ?>
      <section id="secQUniform" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Qualidade • Uniformidade (%)</h2>
        <p id="q-meta-uniform" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartQUniform"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secQPmbVar', $allowedSections, true)): ?>
      <section id="secQPmbVar" class="card rounded-xl2 bg-brand-surface p-5">
        <div class="flex items-start justify-between gap-2 mb-1">
          <div>
            <h2 class="font-semibold">Qualidade • PMB por variedade</h2>
            <p id="q-pmb-meta" class="text-xs text-brand-muted">-</p>
          </div>
          <button id="btnQPmbFilters" type="button" class="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-brand-line bg-white text-brand-text hover:bg-brand-surface-strong shadow-sm transition">
            <span aria-hidden="true" class="text-sm leading-none">&equiv;</span>
            <span class="font-semibold">Filtros</span>
          </button>
        </div>
        <canvas id="chartQPmbVar"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secQBulbosVar', $allowedSections, true)): ?>
      <section id="secQBulbosVar" class="card rounded-xl2 bg-brand-surface p-5">
        <div class="flex items-start justify-between gap-2 mb-1">
          <div>
            <h2 class="font-semibold">Qualidade • Nº Bulbos/saco por variedade</h2>
            <p id="q-bulbos-meta" class="text-xs text-brand-muted">-</p>
          </div>
          <button id="btnQBulbosFilters" type="button" class="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-brand-line bg-white text-brand-text hover:bg-brand-surface-strong shadow-sm transition">
            <span aria-hidden="true" class="text-sm leading-none">&equiv;</span>
            <span class="font-semibold">Filtros</span>
          </button>
        </div>
        <canvas id="chartQBulbosVar"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdSacos', $allowedSections, true)): ?>
      <section id="secProdSacos" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-3">Produção • Sacos (total) e por colaborador</h2>
        <canvas id="chartProdSacos"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdRomaneio', $allowedSections, true)): ?>
      <section id="secProdRomaneio" class="card rounded-xl2 bg-brand-surface p-5">
        <div class="flex items-start justify-between gap-2 mb-1">
          <h2 class="font-semibold">Produção • Romaneio por Caixa</h2>
          <button id="btnProdRomFilters" type="button" class="inline-flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg border border-brand-line bg-white text-brand-text hover:bg-brand-surface-strong shadow-sm transition">
            <span aria-hidden="true" class="text-sm leading-none">&equiv;</span>
            <span class="font-semibold">Filtros</span>
          </button>
        </div>
        <canvas id="chartProdRomaneio"></canvas>
      </section>
      <?php endif; ?>


      <div id="modalProdRom" class="modal-backdrop hidden">
        <div class="modal-compact">
          <div class="modal-head">
            <h3>Filtros - Romaneio por Caixa</h3>
            <button type="button" class="close-btn" data-close-modal="1" aria-label="Fechar">&times;</button>
          </div>
          <?php if (!empty($prodRomVarietyNames)): ?>
          <div class="mb-3">
            <p class="text-[11px] uppercase tracking-wide text-brand-muted">Variedades</p>
            <div id="prodRomaneioVarietyPicker" class="mt-2 flex flex-wrap gap-2 text-xs"></div>
          </div>
          <?php endif; ?>
          <div class="footer">
            <button type="button" class="px-3 py-1.5 text-sm rounded-lg border border-brand-line text-brand-text hover:bg-brand-surface-strong" data-close-modal="1">Fechar</button>
          </div>
        </div>
      </div>
      <?php if (in_array('secProdAting', $allowedSections, true)): ?>
      <section id="secProdAting" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Meta × Sacos Beneficiados/Dia</h2>
        <p id="prod-ating-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdAting"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdCarreg', $allowedSections, true)): ?>
      <section id="secProdCarreg" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Carregamento (h)</h2>
        <p id="prod-carr-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdCarreg"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdDesc', $allowedSections, true)): ?>
      <section id="secProdDesc" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Descarregamento (h)</h2>
        <p id="prod-desc-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdDesc"></canvas>
      </section>
      <?php endif; ?>
      
      <?php if (in_array('secProdParada', $allowedSections, true)): ?>
      <section id="secProdParada" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Máquina parada (h)</h2>
        <p id="prod-parada-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdParada"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdAprov', $allowedSections, true)): ?>
      <section id="secProdAprov" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Aproveitamento (%)</h2>
        <p id="prod-aprov-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdAprov"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazCarreg', $allowedSections, true)): ?>
      <section id="secFazCarreg" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Fazenda • Carregamento (h)</h2>
        <p id="faz-carreg-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaCarreg"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazPessoas', $allowedSections, true)): ?>
      <section id="secFazPessoas" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Fazenda • Pessoas no Campo</h2>
        <p id="faz-pessoas-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaPessoas"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazColhedora', $allowedSections, true)): ?>
      <section id="secFazColhedora" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Fazenda • Colhedora</h2>
        <p id="faz-colhedora-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaColhedora"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secPie', $allowedSections, true)): ?>
      <section id="secPie" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-3">Fazenda • Big bag por Variedade</h2>
        <canvas id="chartPie"></canvas>
      </section>
      <?php endif; ?>
    </div>
    <footer class="mt-12 pt-8 border-t border-brand-line text-center">
      <p class="text-sm text-brand-muted">Powered by TI - Grupo W3 © <?php echo date('Y'); ?></p>
    </footer>
  </div>

  <!-- FAB só em fullscreen -->
  <div class="fs-only fixed bottom-5 right-5 z-50">
    <button id="btnGraphsFS" class="btn btn--compact btn-xl shadow-soft bg-brand-primary text-white flex items-center gap-2 rounded-pill">
      <span>▦</span><span>Gráficos</span>
      <span id="btnGraphsBadgeFS" class="badge bg-white text-brand-primary">0</span>
    </button>
  </div>

  <!-- MODAL DE SELEÇÃO DE GRÁFICOS + DATAS -->
  <div id="graphsModal" class="hidden" role="dialog" aria-modal="true">
    <div class="modal-overlay"></div>
    <div class="modal-shell">
      <div class="modal-card card rounded-xl2 bg-brand-surface p-5 relative overflow-hidden">
        <button id="modalClose" class="absolute right-3 top-3 text-brand-muted hover:text-brand-text text-lg">✕</button>

        <div class="flex items-center justify-between mb-3">
          <h3 class="text-lg font-semibold">Selecionar Gráficos</h3>
          <span id="modalCount" class="text-xs text-brand-muted">0 selecionados</span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
          <div>
            <label class="text-xs text-brand-muted">De</label>
            <input id="modalFrom" type="date" class="mt-1 w-full border rounded-xl2 px-3 py-2"
                   value="<?php echo htmlspecialchars($from->format('Y-m-d')); ?>">
          </div>
          <div>
            <label class="text-xs text-brand-muted">Até</label>
            <input id="modalTo" type="date" class="mt-1 w-full border rounded-xl2 px-3 py-2"
                   value="<?php echo htmlspecialchars($to->format('Y-m-d')); ?>">
          </div>
          <div class="flex items-end">
            <div class="text-xs text-brand-muted">Dica: press F para sair/entrar em tela cheia.</div>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2 mb-3">
          <input id="modalSearch" type="text" placeholder="Buscar..." class="border rounded-xl2 px-3 py-2 text-sm flex-1 min-w-[220px]" />
          <button id="modalSelAll" class="btn btn--compact rounded-pill text-sm">Selecionar todos</button>
          <button id="modalClear"  class="btn btn--compact rounded-pill text-sm">Limpar</button>
        </div>

        <div id="modalGridCols">
          <!-- colunas geradas via JS -->
        </div>

        <div class="mt-4 flex justify-end gap-2 actions-lg">
          <button id="modalCancel" class="btn btn--compact btn-lg border">Cancelar</button>
          <button id="modalApply"  class="btn btn--compact btn-lg bg-brand-primary text-white">Aplicar</button>
        </div>
      </div>
    </div>
  </div>

<script>

  const THEME = { g1:'#9DBF21', g2:'#56A632', g3:'#63AA35', soft:'#cfe87a', red:'#EA0004', yellow:'#FFC107', text:'#1e1e1e' };

  document.getElementById('btnFull')?.addEventListener('click',()=>{
    if(!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
    else document.exitFullscreen();
  });

  // ===== Dados do PHP =====
  const labels  = <?php echo json_encode($labels, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsProdCarr = <?php echo json_encode($labelsProdCarr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsProdCarrISO = <?php echo json_encode($labelsProdCarrISO, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsProdDesc = <?php echo json_encode($labelsProdDesc, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsProdDescISO = <?php echo json_encode($labelsProdDescISO, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const S       = <?php echo json_encode($series, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Comercial HOJE
  const labelsC_H   = <?php echo json_encode($labelsC_H, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const avgPerSC_H  = <?php echo json_encode($avgPerSC_H, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaSC_H   = <?php echo json_encode($mediaPeriodoSC_H, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsCISO_H = <?php echo json_encode($labelsCISO_H, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Comercial ONTEM
  const labelsC_O   = <?php echo json_encode($labelsC_O, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const avgPerSC_O  = <?php echo json_encode($avgPerSC_O, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaSC_O   = <?php echo json_encode($mediaPeriodoSC_O, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const labelsCISO_O = <?php echo json_encode($labelsCISO_O, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Comercial por caixa (series e contagens)
  const comBoxNames       = <?php echo json_encode($comBoxNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comVarietyNames   = <?php echo json_encode($comVarietyNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeBoxSeries  = <?php echo json_encode($comHojeBoxSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeBoxCount   = <?php echo json_encode($comHojeBoxCount, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemBoxSeries = <?php echo json_encode($comOntemBoxSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemBoxCount  = <?php echo json_encode($comOntemBoxCount, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeVarBoxSeries = <?php echo json_encode($comHojeVarBoxSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeVarBoxCount  = <?php echo json_encode($comHojeVarBoxCount, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemVarBoxSeries = <?php echo json_encode($comOntemVarBoxSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemVarBoxCount  = <?php echo json_encode($comOntemVarBoxCount, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Produção — Romaneio por caixa
  const prodRomVarietyNames = <?php echo json_encode($prodRomVarietyNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodRomBoxKeys      = <?php echo json_encode($romBoxKeys, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodRomBoxLabels    = <?php echo json_encode($romBoxLabels, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodRomVarBoxSeries = <?php echo json_encode($prodRomVarBoxSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== NOVO F18 (linhas)
  const f18VarNames     = <?php echo json_encode($f18VarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18SeriesByVar  = <?php echo json_encode($f18SeriesByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalSeries  = <?php echo json_encode($f18TotalSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalMean    = <?php echo json_encode($f18TotalMean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Qualidade por variedade
  const qPmbVarNames       = <?php echo json_encode($qPmbVarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qPmbSeriesByVar    = <?php echo json_encode($qPmbSeriesByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qPmbCountByVar     = <?php echo json_encode($qPmbCountByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qPmbMean           = <?php echo json_encode($qPmbMean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qBulbosVarNames    = <?php echo json_encode($qBulbosVarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qBulbosSeriesByVar = <?php echo json_encode($qBulbosSeriesByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qBulbosCountByVar  = <?php echo json_encode($qBulbosCountByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const qBulbosMean        = <?php echo json_encode($qBulbosMean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: médias gerais (minutos)
  const mediaDesc  = <?php echo json_encode($mediaDesc, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // minutos
  const mediaParada = <?php echo json_encode($mediaParada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // minutos
  const mediaAprov = <?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  const mediaPelada    = <?php echo json_encode($mediaPelada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaDefeitos  = <?php echo json_encode($mediaDefeitos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaUniform   = <?php echo json_encode($mediaUniform, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // TIPOS + SÉRIES POR TIPO (produção, fazenda e logística) — minutos
  const typesProd     = <?php echo json_encode(array_values($typesProd), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const typesProdDesc = <?php echo json_encode(array_values($typesProdDesc), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const typesFaz      = <?php echo json_encode(array_values($typesFaz),  JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== LOGÍSTICA (2 veículos + média) — minutos
  const typesLogSel   = <?php echo json_encode(array_values($typesLogSel), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const logTiposSel     = <?php echo json_encode($seriesLogTiposSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const logDailyMeanSel = <?php echo json_encode($logDailyMeanSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const logDailySumSel  = <?php echo json_encode($logDailySumSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const logDailyCntSel  = <?php echo json_encode($logDailyCntSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaLogSel     = <?php echo json_encode($mediaLogSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

  // Produção / Fazenda — minutos
  const prodCarrTipos = <?php echo json_encode($seriesProdCarrTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescTipos = <?php echo json_encode($seriesProdDescTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrTipos  = <?php echo json_encode($seriesFazCarrTipos,  JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: médias diárias (entre tipos) — minutos
  const prodCarrDailyMean = <?php echo json_encode($prodCarrDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodCarrDailySum  = <?php echo json_encode($prodCarrDailySumArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodCarrDailyCnt  = <?php echo json_encode($prodCarrDailyCntArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescDailyMean = <?php echo json_encode($prodDescDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescDailySum  = <?php echo json_encode($prodDescDailySumArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescDailyCnt  = <?php echo json_encode($prodDescDailyCntArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrDailyMean  = <?php echo json_encode($fazCarrDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  
  const mediaTMC_period   = <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min
  const mediaTMD_period   = <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

  // Datas ISO gerais
  const labelsISO  = <?php echo json_encode($labelsISO, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== BRUTOS da Fazenda Carregamento — minutos
  const fazCarrRawSum = <?php echo json_encode($fazCarrRawSumArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrRawCnt = <?php echo json_encode($fazCarrRawCntArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaFazCarr_period = <?php echo json_encode($mediaFazCarr_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

  // NOVO: médias separadas Pessoas/Colhedora
  const mediaF17 = <?php echo json_encode($mediaF17, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaF19 = <?php echo json_encode($mediaF19, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  
  // META (diário)
  const atingPct       = <?php echo json_encode($atingPct, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const atingMetaMedia = <?php echo json_encode($atingMetaMedia, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // +++ NOVO: KPI Safra + séries para re-filtrar +++
  const atingSafraPct  = <?php echo json_encode($atingSafraPct, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const totalRealSafra = <?php echo json_encode($totalRealSafra, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const totalMetaSafra = <?php echo json_encode($totalMetaSafra, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const diasComMeta    = <?php echo json_encode($diasComMeta, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const diasComDados   = <?php echo json_encode($diasComDados, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const diasAtingidos  = <?php echo json_encode($diasAtingidos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const metaSeriesByDay = <?php echo json_encode($metaSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const realSeriesByDay = <?php echo json_encode($series['p15_dia'], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== Estado base e refs dos gráficos
  const BASE = {
    labels: [...labels],
    labelsISO: [...labelsISO],
    labelsProdCarr: [...labelsProdCarr],
    labelsProdCarrISO: [...labelsProdCarrISO],
    labelsProdDesc: [...labelsProdDesc],
    labelsProdDescISO: [...labelsProdDescISO],
    S: JSON.parse(JSON.stringify(S)),

    // Comercial HOJE
    labelsC_H: [...labelsC_H],
    labelsCISO_H: [...labelsCISO_H],
    avgPerSC_H: [...avgPerSC_H],
    mediaSC_H: mediaSC_H,

    // Comercial ONTEM
    labelsC_O: [...labelsC_O],
    labelsCISO_O: [...labelsCISO_O],
    avgPerSC_O: [...avgPerSC_O],
    mediaSC_O: mediaSC_O,

    // Comercial por caixa
    comBoxNames: [...(comBoxNames || [])],
    comHojeBoxSeries: JSON.parse(JSON.stringify(comHojeBoxSeries || {})),
    comHojeBoxCount:  JSON.parse(JSON.stringify(comHojeBoxCount  || {})),
    comOntemBoxSeries: JSON.parse(JSON.stringify(comOntemBoxSeries || {})),
    comOntemBoxCount:  JSON.parse(JSON.stringify(comOntemBoxCount  || {})),
    comVarietyNames: [...(comVarietyNames || [])],
    comHojeVarBoxSeries: JSON.parse(JSON.stringify(comHojeVarBoxSeries || {})),
    comHojeVarBoxCount:  JSON.parse(JSON.stringify(comHojeVarBoxCount  || {})),
    comOntemVarBoxSeries: JSON.parse(JSON.stringify(comOntemVarBoxSeries || {})),
    comOntemVarBoxCount:  JSON.parse(JSON.stringify(comOntemVarBoxCount  || {})),

    prodRomVarietyNames: [...(prodRomVarietyNames || [])],
    prodRomBoxKeys:      [...(prodRomBoxKeys || [])],
    prodRomBoxLabels:    JSON.parse(JSON.stringify(prodRomBoxLabels || {})),
    prodRomVarBoxSeries: JSON.parse(JSON.stringify(prodRomVarBoxSeries || {})),

    typesProd: [...typesProd],
    typesProdDesc: [...typesProdDesc],
    typesFaz:  [...typesFaz],

    prodCarrTipos: JSON.parse(JSON.stringify(prodCarrTipos)),
    prodDescTipos: JSON.parse(JSON.stringify(prodDescTipos)),
    fazCarrTipos:  JSON.parse(JSON.stringify(fazCarrTipos)),

    // LOGÍSTICA (2 veículos + média)
    typesLogSel: [...typesLogSel],
    logTiposSel: JSON.parse(JSON.stringify(logTiposSel)),
    logDailyMeanSel: [...logDailyMeanSel],
    logDailySumSel: [...logDailySumSel],
    logDailyCntSel: [...logDailyCntSel],
    mediaLogSel: mediaLogSel,

    mediaParada: mediaParada,

    // médias diárias (entre tipos) em minutos
    prodCarrDailyMean: [...prodCarrDailyMean],
    prodCarrDailySum: [...prodCarrDailySum],
    prodCarrDailyCnt: [...prodCarrDailyCnt],
    prodDescDailyMean: [...prodDescDailyMean],
    prodDescDailySum: [...prodDescDailySum],
    prodDescDailyCnt: [...prodDescDailyCnt],
    fazCarrDailyMean: [...fazCarrDailyMean],

    // BRUTOS FAZENDA
    fazCarrRawSum: [...fazCarrRawSum],
    fazCarrRawCnt: [...fazCarrRawCnt],
    mediaFazCarr_period: mediaFazCarr_period,

    // META (% diário)
    atingPct: [...atingPct],
    atingMetaMedia: atingMetaMedia,

    // +++ KPI SAFRA +++
    atingSafraPct: atingSafraPct,
    totalRealSafra: totalRealSafra,
    totalMetaSafra: totalMetaSafra,
    diasComMeta: diasComMeta,
    diasComDados: diasComDados,
    diasAtingidos: diasAtingidos,
    metaSeriesByDay: [...metaSeriesByDay],
    realSeriesByDay: [...realSeriesByDay],

    qPmbVarNames: [...qPmbVarNames],
    qPmbSeriesByVar: JSON.parse(JSON.stringify(qPmbSeriesByVar)),
    qPmbCountByVar: JSON.parse(JSON.stringify(qPmbCountByVar)),
    qPmbMean: qPmbMean,
    qBulbosVarNames: [...qBulbosVarNames],
    qBulbosSeriesByVar: JSON.parse(JSON.stringify(qBulbosSeriesByVar)),
    qBulbosCountByVar: JSON.parse(JSON.stringify(qBulbosCountByVar)),
    qBulbosMean: qBulbosMean,

    // F18
    f18VarNames: [...f18VarNames],
    f18SeriesByVar: JSON.parse(JSON.stringify(f18SeriesByVar)),
    f18TotalSeries: [...f18TotalSeries],
    f18TotalMean: f18TotalMean
  };
  const CH = {}; // refs dos gráficos
  let logMeanMap = {}; // última média por tipo de veículo (logística)
  let prodCarrMeanMap = {}; // última média por tipo - produção carregamento
  let prodDescMeanMap = {}; // última média por tipo - produção descarregamento
  let fazCarrMeanMap = {}; // última média por tipo - fazenda carregamento

  // ===== Ícones
  const ico = {
    comercial: `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M3 12h18M7 8h10M9 16h6" fill="none" stroke="#273418" stroke-width="2" stroke-linecap="round"/></svg>`,
    logistica: `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M3 7h10v6H3zM13 9h5l3 4v4h-8z" fill="none" stroke="#273418" stroke-width="2" stroke-linejoin="round"/><circle cx="7" cy="17" r="2" stroke="#273418" stroke-width="2" fill="none"/><circle cx="17" cy="17" r="2" stroke="#273418" stroke-width="2" fill="none"/></svg>`,
    qualidade: `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M4 12l4 4 8-8" fill="none" stroke="#273418" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
    producao:  `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M4 17h4V7H4zM10 17h4V3h-4zM16 17h4V11h-4z" fill="none" stroke="#273418" stroke-width="2"/></svg>`,
    fazenda:   `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M3 12l9-7 9 7v8H3zM7 20v-6h10v6" fill="none" stroke="#273418" stroke-width="2" stroke-linejoin="round"/></svg>`,
    pizza:     `<svg viewBox="0 0 24 24" class="w-6 h-6"><path d="M12 2a10 10 0 1 0 10 10" fill="none" stroke="#273418" stroke-width="2"/><path d="M12 2v10h10" fill="none" stroke="#273418" stroke-width="2"/></svg>`,
    pessoas:   `<svg viewBox="0 0 24 24" class="w-6 h-6"><circle cx="8" cy="8" r="3" stroke="#273418" stroke-width="2" fill="none"/><circle cx="16" cy="8" r="3" stroke="#273418" stroke-width="2" fill="none"/><path d="M4 20c0-3 3-5 4-5s4 2 4 5M12 20c0-3 3-5 4-5s4 2 4 5" fill="none" stroke="#273418" stroke-width="2"/></svg>`,
    tempo:     `<svg viewBox="0 0 24 24" class="w-6 h-6"><circle cx="12" cy="12" r="9" fill="none" stroke="#273418" stroke-width="2"/><path d="M12 7v5l4 3" fill="none" stroke="#273418" stroke-width="2" stroke-linecap="round"/></svg>`
  };

  // ====== Catálogo com role explícito (+ secProdAtingSafra)
  const ALL_SECTIONS = [
    {id:'secProdAtingSafra', label:'Atingimento da safra (KPI)', icon:ico.producao, role:'producao'},

    {id:'secComercial',      label:'Preço por SC (Atual)',           icon:ico.comercial, role:'comercial'},
    {id:'secComercialOntem', label:'Preço por SC (Realizado)',       icon:ico.comercial, role:'comercial'},
    {id:'secLogistica',      label:'Tempo transporte',                icon:ico.logistica, role:'logistica'},
    {id:'secQPelada',        label:'Cebola Pelada (%)',              icon:ico.qualidade, role:'qualidade'},
    {id:'secQDefeitos',      label:'Defeitos (%)',                   icon:ico.qualidade, role:'qualidade'},
    {id:'secQUniform',       label:'Uniformidade (%)',               icon:ico.qualidade, role:'qualidade'},
    {id:'secQPmbVar',        label:'PMB por variedade',              icon:ico.qualidade, role:'qualidade'},
    {id:'secQBulbosVar',     label:'Nº bulbos/saco por variedade',   icon:ico.qualidade, role:'qualidade'},
    {id:'secProdSacos',      label:'Sacos & por colaborador',        icon:ico.producao,  role:'producao'},
    {id:'secProdRomaneio',   label:'Romaneio por caixa',              icon:ico.producao,  role:'producao'},
    {id:'secProdAting',      label:'Meta × Sacos Beneficiados/Dia', icon:ico.producao,  role:'producao' },
    {id:'secProdCarreg',     label:'Carregamento por tipo',          icon:ico.producao,  role:'producao'},
    {id:'secProdDesc',       label:'Descarregamento por tipo',       icon:ico.producao,  role:'producao'},
    {id:'secProdParada',     label:'Máquina parada (h)',             icon:ico.producao,  role:'producao'},
    {id:'secProdAprov',      label:'Aproveitamento (%)',             icon:ico.producao,  role:'producao'},
    {id:'secFazCarreg',      label:'Carregamento por tipo',          icon:ico.fazenda,   role:'fazenda'},
    {id:'secFazPessoas',     label:'Pessoas no Campo',               icon:ico.fazenda,   role:'fazenda'},
    {id:'secFazColhedora',   label:'Colhedora Big Bag',              icon:ico.fazenda,   role:'fazenda'},
    {id:'secPie',            label:'Big Bag por variedade',          icon:ico.fazenda,   role:'fazenda'},
  ];

  const ALLOWED_SEC_IDS = <?php echo json_encode(array_values($allowedSections), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  let selectedSecs       = new Set(<?php echo json_encode(array_values($preSelectedSecs), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  const CATALOG = ALL_SECTIONS.filter(s => ALLOWED_SEC_IDS.includes(s.id));

  // ===== Helpers de tempo: agora em HORAS =====
  const minutesToHHMM = (min) => {
    if (min == null || isNaN(min)) return null;
    const m = Math.round(Number(min));
    const h = Math.floor(m / 60);
    const mm = String(m % 60).padStart(2, '0');
    return `${String(h).padStart(2,'0')}:${mm}`;
  };
  const minToHours = (v) => (v==null || isNaN(v) ? null : (Number(v)/60));
  const seriesMinToHours = (arr) => (arr||[]).map(minToHours);
  const dictSeriesMinToHours = (dict) => {
    const out = {};
    for (const k of Object.keys(dict||{})) out[k] = seriesMinToHours(dict[k]);
    return out;
  };

  const moneyFmt = (n) => Number(n).toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 });

  // Metas em HORAS (com HH:MM entre parênteses)
  function setMetaHours(elId, minutesVal){
    const el = document.getElementById(elId);
    if (!el) return;
    if (minutesVal==null || isNaN(minutesVal)) { el.textContent = '—'; return; }
    const hh = Number(minutesVal)/60;
    const hhmm = minutesToHHMM(minutesVal);
    el.textContent = `• Média no período: ${hh.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 })} h${hhmm?` (${hhmm})`:''}`;
  }
  function setTypeMetaHours(elId, meanMap){
    const el = document.getElementById(elId);
    if (!el) return;
    const entries = Object.entries(meanMap || {}).filter(([, v]) => v != null && !Number.isNaN(v));
    if (!entries.length) { el.textContent = '—'; return; }

    const parts = entries.map(([type, min]) => {
      const hours = Number(min) / 60;
      return `${type}: ${hours.toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 3 })} h`;
    });

    el.textContent = '• ' + parts.join(' • ');
  }
  function setMetaMoney(el, val) {
    if (!el) return;
    el.textContent = (val == null || isNaN(val))
      ? '—'
      : `• Média no período: R$ ${moneyFmt(val)}`;
  }
  function setMetaPercent(elId, val){
    const el = document.getElementById(elId);
    if (!el) return;
    if (val==null || isNaN(val)) { el.textContent = '—'; return; }
    el.textContent = `• Média no período: ${Number(val).toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 })} %`;
  }

  // ===== Modal & seleção de seções (inalterado)
  const CHART_SECS_WITH_TIME = new Set(['secLogistica','secProdCarreg','secProdDesc','secProdParada','secFazCarreg']); // gráficos que exibem horas

  const graphsModal = document.getElementById('graphsModal');
  const btnGraphs   = document.getElementById('btnGraphs');
  const btnGraphsFS = document.getElementById('btnGraphsFS');
  const btnGraphsBadge   = document.getElementById('btnGraphsBadge');
  const btnGraphsBadgeFS = document.getElementById('btnGraphsBadgeFS');
  const modalClose  = document.getElementById('modalClose');
  const modalCancel = document.getElementById('modalCancel');
  const modalApply  = document.getElementById('modalApply');
  const modalSelAll = document.getElementById('modalSelAll');
  const modalClear  = document.getElementById('modalClear');
  const modalSearch = document.getElementById('modalSearch');
  const modalGridCols = document.getElementById('modalGridCols');
  const modalCount  = document.getElementById('modalCount');

  const modalFrom = document.getElementById('modalFrom');
  const modalTo   = document.getElementById('modalTo');

  function openModal(){
    graphsModal.classList.remove('hidden');
    modalSearch.value='';
    renderModalColumns();
  }
  function closeModal(){ graphsModal.classList.add('hidden'); }
  btnGraphs?.addEventListener('click', openModal);
  btnGraphsFS?.addEventListener('click', openModal);
  modalClose?.addEventListener('click', closeModal);
  modalCancel?.addEventListener('click', closeModal);

  function updateCountBadge(setObj){
    const count = (setObj instanceof Set) ? setObj.size : selectedSecs.size;
    modalCount.textContent = `${count} selecionados`;
    if (btnGraphsBadge)   btnGraphsBadge.textContent   = String(count);
    if (btnGraphsBadgeFS) btnGraphsBadgeFS.textContent = String(count);
  }

  const ROLE_ORDER = [
    {key:'comercial', title:'Comercial', icon:ico.comercial},
    {key:'logistica', title:'Logística', icon:ico.logistica},
    {key:'qualidade', title:'Qualidade', icon:ico.qualidade},
    {key:'producao',  title:'Produção',  icon:ico.producao},
    {key:'fazenda',   title:'Fazenda',   icon:ico.fazenda},
  ];

  function makeTile(section, currentSet){
    const tile = document.createElement('button');
    tile.type='button';
    tile.className = 'sel-tile ' + (currentSet.has(section.id) ? 'active' : '');
    tile.dataset.id = section.id;
    tile.setAttribute('aria-pressed', currentSet.has(section.id) ? 'true' : 'false');

    const icoWrap = document.createElement('span');
    icoWrap.className = 'sel-ico';
    icoWrap.innerHTML = section.icon;

    const title = document.createElement('div');
    title.className = 'text-base font-semibold';
    title.textContent = section.label;

    const check = document.createElement('span');
    check.className = 'check';
    check.innerHTML = '✓';

    tile.appendChild(icoWrap);
    tile.appendChild(title);
    tile.appendChild(check);

    tile.addEventListener('click', ()=>{
      if (currentSet.has(section.id)) currentSet.delete(section.id); else currentSet.add(section.id);
      const isActive = currentSet.has(section.id);
      tile.classList.toggle('active', isActive);
      tile.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      updateCountBadge(currentSet);
      graphsModal.dataset.tmpSelection = JSON.stringify([...currentSet]);
      const col = tile.closest('.role-col');
      if (col) {
        const countEl = col.querySelector('.role-count');
        const idsInCol = Array.from(col.querySelectorAll('.sel-tile')).map(b => b.dataset.id);
        const checkedInCol = idsInCol.filter(id => currentSet.has(id)).length;
        if (countEl) countEl.textContent = `${checkedInCol} selecionado(s)`;
      }
    });

    return tile;
  }

  function renderModalColumns(){
    const q = (modalSearch.value||'').trim().toLowerCase();
    modalGridCols.innerHTML = '';
    const current = new Set(selectedSecs);

    ROLE_ORDER.forEach(({key, title, icon})=>{
      const col = document.createElement('div');
      col.className = 'role-col';

      const header = document.createElement('div');
      header.className = 'role-header';
      const h = document.createElement('div');
      h.className = 'role-title';
      h.innerHTML = `${icon}<span>${title}</span>`;
      const count = document.createElement('div');
      count.className = 'role-count';
      header.appendChild(h);
      header.appendChild(count);

      col.appendChild(header);

      const items = CATALOG.filter(s => s.role===key)
                           .filter(s => !q || s.label.toLowerCase().includes(q));

      items.forEach(s => col.appendChild(makeTile(s, current)));

      const checkedInCol = items.map(i=>i.id).filter(id => current.has(id)).length;
      count.textContent = `${checkedInCol} selecionado(s)`;

      modalGridCols.appendChild(col);
    });

    graphsModal.dataset.tmpSelection = JSON.stringify([...current]);
    updateCountBadge(current);
  }

  modalSearch?.addEventListener('input', renderModalColumns);

  document.getElementById('modalSelAll')?.addEventListener('click', ()=>{
    const tmp = new Set(selectedSecs);
    const visibleIds = Array.from(document.querySelectorAll('#modalGridCols .sel-tile')).map(b=>b.dataset.id);
    visibleIds.forEach(id=>tmp.add(id));
    selectedSecs = tmp;
    renderModalColumns();
  });

  document.getElementById('modalClear')?.addEventListener('click', ()=>{
    const tmp = new Set(selectedSecs);
    const visibleIds = Array.from(document.querySelectorAll('#modalGridCols .sel-tile')).map(b=>b.dataset.id);
    visibleIds.forEach(id=>tmp.delete(id));
    selectedSecs = tmp;
    renderModalColumns();
  });

  graphsModal?.addEventListener('click', (e)=>{ if (e.target.classList.contains('modal-overlay')) closeModal(); });

  function setupSimpleModal(btnId, modalId){
    const btn = document.getElementById(btnId);
    const modal = document.getElementById(modalId);
    if (!btn || !modal) return;
    const close = ()=> modal.classList.add('hidden');
    modal.querySelectorAll('[data-close-modal]').forEach(el => el.addEventListener('click', close));
    modal.addEventListener('click', (e)=>{ if (e.target === modal) close(); });
    btn.addEventListener('click', ()=> modal.classList.remove('hidden'));
  }

  setupSimpleModal('btnComercialHojeFilters', 'modalComercialHoje');
  setupSimpleModal('btnComercialOntemFilters', 'modalComercialOntem');
  setupSimpleModal('btnProdRomFilters', 'modalProdRom');
  setupSimpleModal('btnQPmbFilters', 'modalQPmb');
  setupSimpleModal('btnQBulbosFilters', 'modalQBulbos');

  // Inclui sec=... no submit do cabeçalho
  document.querySelector('form[method="GET"]')?.addEventListener('submit',()=>{
    const hidden = document.getElementById('secHiddenInputs');
    if (!hidden) return;
    hidden.innerHTML='';
    const inp=document.createElement('input'); inp.type='hidden'; inp.name='sec'; inp.value=[...selectedSecs].join(',');
    hidden.appendChild(inp);
  });

  function applySecFilter(){
    if (!selectedSecs || selectedSecs.size === 0) {
      selectedSecs = new Set(CATALOG.map(s=>s.id));
    }
    const visible = new Set(selectedSecs);
    CATALOG.forEach(s=>{
      const el = document.getElementById(s.id);
      if (el) el.style.display = visible.has(s.id) ? '' : 'none';
    });
    updateGridCols();
  }
  function pushSecToQuery(){
    const url = new URL(location.href);
    if (!selectedSecs || selectedSecs.size===0 || selectedSecs.size === CATALOG.length) url.searchParams.delete('sec');
    else url.searchParams.set('sec', [...selectedSecs].join(','));
    history.replaceState(null,'', url.toString());
  }

  // ======= FILTRAGEM DE DATAS NO CLIENTE =====
  function idxRangeByDateISO(allISO, dFrom, dTo){
    const from = dFrom ? new Date(dFrom) : null;
    const to   = dTo   ? new Date(dTo)   : null;
    const keep = [];
    for(let i=0;i<allISO.length;i++){
      const d = new Date(allISO[i]);
      if ((from && d < from) || (to && d > to)) continue;
      keep.push(i);
    }
    return keep;
  }
  function sliceByIdx(arr, keepIdx){
    return keepIdx.map(i => (i>=0 && i<arr.length) ? arr[i] : null);
  }

function avgNonNull(arr){
  let s = 0, c = 0;
  for (const v of (arr || [])) {
    if (v == null) continue;
    const n = Number(v);
    if (Number.isNaN(n)) continue;
    if (n <= 0) continue;        // <- ignora 0 e negativos
    s += n; c++;
  }
  return c ? (s / c) : null;
}

  function avgFromSumCnt(sumArr, cntArr){
    let totalSum = 0, totalCnt = 0;
    const len = Math.min(sumArr ? sumArr.length : 0, cntArr ? cntArr.length : 0);
    for (let i=0; i<len; i++) {
      const sumVal = sumArr[i];
    const cntVal = cntArr[i];
    if (sumVal == null || cntVal == null) continue;
    const s = Number(sumVal);
    const c = Number(cntVal);
    if (Number.isNaN(s) || Number.isNaN(c) || c <= 0) continue;
    totalSum += s;
    totalCnt += c;
        }
    return totalCnt ? (totalSum / totalCnt) : null;
  }

function buildTypeDatasets(types, dictMinSeries, keepIdx, labelsFiltered, colorFn, lineOpts = {}, meanPrefix = 'Média', labelFn = (t)=>t, meanMode = 'period'){
  const ds = [];
  const meanMap = {};

  for (const type of (types || [])){
    const baseSeries = dictMinSeries?.[type] || [];
    const serieMin = keepIdx ? sliceByIdx(baseSeries, keepIdx) : baseSeries;
    const serieH = seriesMinToHours(serieMin);
    const label = labelFn(type);
    ds.push(mkLine(label, serieH, colorFn(type), 'y', lineOpts));

    const len = (labelsFiltered || []).length || serieMin.length;
    let meanLineMin = new Array(len).fill(null);
    if (meanMode === 'running') {
      let sum = 0;
      let cnt = 0;
      meanLineMin = serieMin.map((v) => {
        if (v == null || Number.isNaN(Number(v)) || Number(v) <= 0) return cnt ? (sum / cnt) : null;
        sum += Number(v);
        cnt += 1;
        return sum / cnt;
      });
      // usa a última média válida para meta
      let lastMean = null;
      for (let i = meanLineMin.length - 1; i >= 0; i--) {
        const v = meanLineMin[i];
        if (v != null && !Number.isNaN(v)) { lastMean = v; break; }
      }
      meanMap[type] = lastMean;
    } else {
      const meanMin = avgNonNull(serieMin);
      meanMap[type] = meanMin;
      meanLineMin = new Array(len).fill(meanMin);
    }

    const meanLine = meanLineMin.map(minToHours);
    ds.push(mkLine(`${meanPrefix} ${label}`, meanLine, colorFn(type), 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));
  }

  return { datasets: ds, meanMap };
}

function projectTypeSeriesByDate(dictSeries, baseLabelsISO, targetLabelsISO){
  const idxByDate = new Map();
  (baseLabelsISO || []).forEach((d, idx) => {
    if (!idxByDate.has(d)) idxByDate.set(d, idx);
  });

  const projected = {};
  Object.entries(dictSeries || {}).forEach(([type, series]) => {
    projected[type] = (targetLabelsISO || []).map((d) => {
      const idx = idxByDate.get(d);
      return idx == null ? null : (series?.[idx] ?? null);
    });
  });

  return projected;
}
  // ======== Helpers Comercial por caixa =========
  function combineBoxSeries(seriesMap, countMap, selectedBoxes, len){
    const boxes = (selectedBoxes && selectedBoxes.length)
      ? selectedBoxes
    : Object.keys(seriesMap || {});
  const sum = new Array(len).fill(0);
  const weights = new Array(len).fill(0);
  for (const box of boxes){
    const serie = seriesMap?.[box] || [];
    const counts = countMap?.[box] || [];
    for (let i=0;i<len;i++){
      const v = serie[i];
      const c = counts[i];
      if (v == null || Number.isNaN(v)) continue;
      const cNum = Number(c);
      if (Number.isNaN(cNum) || cNum <= 0) continue;
      const vNum = Number(v);
      if (Number.isNaN(vNum)) continue;
      sum[i] += vNum * cNum;
      weights[i] += cNum;
    }
  }
  const out = sum.map((s, i) => weights[i] > 0 ? (s / weights[i]) : null);
  return { series: out, weights };
}
function weightedMean(series, weights){
  let ws=0, wq=0;
  for (let i=0;i<series.length;i++){
    const p = series[i], q = weights[i];
    if (p != null && !Number.isNaN(p) && Number(p) > 0 && q != null && !Number.isNaN(q) && Number(q) > 0){
      ws += Number(p) * Number(q);
      wq += Number(q);
    }
  }
  return (wq>0) ? (ws / wq) : null;
}
function buildDailyMeanLine(seriesMap, countMap, selectedBoxes, len, keepIdx){
  const idx = (keepIdx && keepIdx.length) ? keepIdx : Array.from({ length: len }, (_, i) => i);
  const { series, weights } = combineBoxSeries(seriesMap, countMap, selectedBoxes, len);
  const perDay = sliceByIdx(series, idx);
  const perDayWeights = sliceByIdx(weights, idx);
  return {
    perDay,
    weights: perDayWeights,
    periodMean: weightedMean(perDay, perDayWeights),
  };
}
function combineVarSeries(seriesByVar, countByVar, selectedVars, len){
  const vars = (selectedVars && selectedVars.length)
    ? selectedVars
    : Object.keys(seriesByVar || {});
  const sum = new Array(len).fill(0);
  const weights = new Array(len).fill(0);

  vars.forEach((vn) => {
    const serie = seriesByVar?.[vn] || [];
    const counts = countByVar?.[vn] || [];
    for (let i = 0; i < len; i++){
      const val = serie[i];
      if (val == null || Number.isNaN(val)) continue;
      const numVal = Number(val);
      if (Number.isNaN(numVal)) continue;
      const weightRaw = counts[i];
      const weight = Number.isNaN(Number(weightRaw)) ? 1 : Number(weightRaw);
      if (weight <= 0) continue;
      sum[i] += numVal * weight;
      weights[i] += weight;
    }
  });

  return {
    series: sum.map((s, i) => weights[i] ? (s / weights[i]) : null),
    weights,
  };
}
function aggregateVarietySeries(periodKey, selectedVarieties){
  const allVarieties = BASE.comVarietyNames || [];
  const baseSeries = (periodKey === 'H') ? BASE.comHojeBoxSeries : BASE.comOntemBoxSeries;
  const baseCount  = (periodKey === 'H') ? BASE.comHojeBoxCount  : BASE.comOntemBoxCount;
  const varSeries  = (periodKey === 'H') ? BASE.comHojeVarBoxSeries : BASE.comOntemVarBoxSeries;
  const varCounts  = (periodKey === 'H') ? BASE.comHojeVarBoxCount  : BASE.comOntemVarBoxCount;
  const hasVarData = allVarieties.length && varSeries && Object.keys(varSeries).length;
  if (!hasVarData) {
    return { seriesMap: baseSeries, countMap: baseCount };
  }
  const normSel = (selectedVarieties && selectedVarieties.length)
    ? Array.from(new Set(selectedVarieties))
    : [...allVarieties];
  if (normSel.length === allVarieties.length) {
    return { seriesMap: baseSeries, countMap: baseCount };
  }
  const len = (periodKey === 'H') ? BASE.labelsC_H.length : BASE.labelsC_O.length;
  const boxes = BASE.comBoxNames || [];
  const outSeries = {};
  const outCounts = {};
  boxes.forEach(box => {
    const sums = new Array(len).fill(0);
    const weights = new Array(len).fill(0);
    normSel.forEach(varName => {
      const serie = varSeries?.[varName]?.[box] || [];
      const counts = varCounts?.[varName]?.[box] || [];
      for (let i=0;i<len;i++){
        const val = serie[i];
        const weight = counts[i];
        if (val == null) continue;
        const numVal = Number(val);
        const numWeight = Number(weight);
        if (Number.isNaN(numVal) || Number.isNaN(numWeight) || numWeight <= 0) continue;
        sums[i] += numVal * numWeight;
        weights[i] += numWeight;
      }
    });
    outSeries[box] = sums.map((s,i)=> weights[i] > 0 ? Number((s / weights[i]).toFixed(3)) : null);
    outCounts[box] = weights.map(w => Number(w));
  });
  return { seriesMap: outSeries, countMap: outCounts };
}
function buildVarPicker(containerId, varNames, initialSel, onChange){
  const el = document.getElementById(containerId);
  if (!el) return;
  let state = new Set(initialSel && initialSel.length ? initialSel : varNames);
  function render(){
    el.innerHTML = '';
    varNames.forEach(vn=>{
      const btn = document.createElement('button');
      const active = state.has(vn);
      btn.type='button';
      btn.className = `px-2 py-1 rounded-full border ${active?'bg-brand-primary text-white border-brand-primary':'bg-white text-brand-text border-brand-line'}`;
      btn.textContent = vn;
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
      btn.addEventListener('click', ()=>{
        if (state.has(vn)) state.delete(vn); else state.add(vn);
        if (state.size === 0) state.add(vn); // nunca vazio
        render();
        onChange(Array.from(state));
      });
      el.appendChild(btn);
    });
    const allBtn = document.createElement('button');
    allBtn.type='button';
    allBtn.className='px-2 py-1 rounded-full border bg-white text-brand-text border-brand-line';
    allBtn.textContent='Todas';
    allBtn.addEventListener('click', ()=>{ state = new Set(varNames); render(); onChange(Array.from(state)); });
    el.appendChild(allBtn);

    onChange(Array.from(state));
  }
  render();
}

function aggregateRomaneioSeries(selectedVarieties){
  const allVar = BASE.prodRomVarietyNames || [];
  const active = (selectedVarieties && selectedVarieties.length) ? selectedVarieties : allVar;
  const boxKeys = BASE.prodRomBoxKeys || [];
  const len = BASE.labels.length;
  const varSeries = BASE.prodRomVarBoxSeries || {};
  const out = {};
  boxKeys.forEach(boxKey => {
    const sums = new Array(len).fill(0);
    const has = new Array(len).fill(false);
    if (active && active.length) {
      active.forEach(varName => {
        const serie = varSeries?.[varName]?.[boxKey] || [];
        for (let i=0;i<len;i++){
          const val = serie[i];
          if (val == null) continue;
          const num = Number(val);
          if (Number.isNaN(num)) continue;
          sums[i] += num;
          has[i] = true;
        }
      });
    }
    out[boxKey] = sums.map((sum, idx) => has[idx] ? Number(sum.toFixed(3)) : null);
  });
  return out;
}

// === Helpers globais usados em vários blocos ===
function isAllNull(arr){
  return !arr || arr.every(v => v == null);
}
function sumNumbers(arr){
  return (arr || []).reduce((s, v) => s + ((v != null && !Number.isNaN(Number(v))) ? Number(v) : 0), 0);
}
function setMetaNumber(elId, val, unit = '', digits = { minimumFractionDigits: 2, maximumFractionDigits: 3 }){
  const el = document.getElementById(elId);
  if (!el) return;
  if (val==null || isNaN(val)) { el.textContent = '-'; return; }
  el.textContent = `• Média no período: ${Number(val).toLocaleString('pt-BR', digits)}${unit ? ` ${unit}` : ''}`;
}

function setProdMetaSummary(realSeries, metaSeries){
  const el = document.getElementById('prod-ating-meta');
  if (!el) return;

  const totalReal = sumNumbers(realSeries);
  const totalMeta = sumNumbers(metaSeries);

  if ((totalReal == null || totalReal <= 0) && (totalMeta == null || totalMeta <= 0)) {
    el.textContent = '—';
    return;
  }

  const fmtNum = (n) => Number(n).toLocaleString('pt-BR', { maximumFractionDigits: 0 });
  const parts = [];
  if (totalReal > 0) parts.push(`Realizado: ${fmtNum(totalReal)} sacos`);
  if (totalMeta > 0) parts.push(`Meta: ${fmtNum(totalMeta)} sacos`);
  if (totalReal > 0 && totalMeta > 0) {
    const pct = (totalReal / totalMeta) * 100;
    parts.push(`Atingimento: ${pct.toLocaleString('pt-BR', { minimumFractionDigits: 0, maximumFractionDigits: 2 })}%`);
  }

  el.textContent = '• ' + parts.join(' • ');
}

function updateProdRomaneioChart(){
  if (!CH.prodRomaneio) return;
  const keep = (window._keepIdx && window._keepIdx.length) ? window._keepIdx : BASE.labels.map((_,i)=>i);
  const labelsF = sliceByIdx(BASE.labels, keep);
  const agg = aggregateRomaneioSeries(window._prodRomVarSel);
  CH.prodRomaneio.data.labels = labelsF;
  const boxKeys = BASE.prodRomBoxKeys || [];
  boxKeys.forEach((boxKey, idx) => {
    const dataset = CH.prodRomaneio.data.datasets?.[idx];
    if (!dataset) return;
    const fullData = agg[boxKey] || [];
    dataset.data = sliceByIdx(fullData, keep);
    dataset.label = BASE.prodRomBoxLabels?.[boxKey] || boxKey;
    dataset.borderColor = colorForRomaneioBox(boxKey);
  });
  CH.prodRomaneio.update();
}

function updateQPmbChart(){
  if (!CH.qPmbVar) return;
  const keep = (window._keepIdx && window._keepIdx.length) ? window._keepIdx : BASE.labels.map((_,i)=>i);
  const labelsF = sliceByIdx(BASE.labels, keep);
  const varNames = BASE.qPmbVarNames || [];
  const sel = (window._qPmbVarSel && window._qPmbVarSel.length) ? window._qPmbVarSel : varNames;
  const selSet = new Set(sel.length ? sel : varNames);

  CH.qPmbVar.data.labels = labelsF;
  varNames.forEach((vn, idx) => {
    const dataset = CH.qPmbVar.data.datasets?.[idx];
    if (!dataset) return;
    dataset.data = sliceByIdx(BASE.qPmbSeriesByVar?.[vn] || [], keep);
    dataset.hidden = !selSet.has(vn);
    dataset.label = vn;
    dataset.borderColor = colorForVar(vn);
  });

  const { series, weights } = combineVarSeries(BASE.qPmbSeriesByVar, BASE.qPmbCountByVar, Array.from(selSet), BASE.labels.length);
  const meanDataset = CH.qPmbVar.data.datasets[varNames.length];
  if (meanDataset) {
    meanDataset.data = sliceByIdx(series, keep);
    meanDataset.hidden = false;
  }
  CH.qPmbVar.update();
  const meanVal = weightedMean(sliceByIdx(series, keep), sliceByIdx(weights, keep));
  setMetaNumber('q-pmb-meta', meanVal, 'kg');
}

function updateQBulbosChart(){
  if (!CH.qBulbosVar) return;
  const keep = (window._keepIdx && window._keepIdx.length) ? window._keepIdx : BASE.labels.map((_,i)=>i);
  const labelsF = sliceByIdx(BASE.labels, keep);
  const varNames = BASE.qBulbosVarNames || [];
  const sel = (window._qBulbosVarSel && window._qBulbosVarSel.length) ? window._qBulbosVarSel : varNames;
  const selSet = new Set(sel.length ? sel : varNames);

  CH.qBulbosVar.data.labels = labelsF;
  varNames.forEach((vn, idx) => {
    const dataset = CH.qBulbosVar.data.datasets?.[idx];
    if (!dataset) return;
    dataset.data = sliceByIdx(BASE.qBulbosSeriesByVar?.[vn] || [], keep);
    dataset.hidden = !selSet.has(vn);
    dataset.label = vn;
    dataset.borderColor = colorForVar(vn);
  });

  const { series, weights } = combineVarSeries(BASE.qBulbosSeriesByVar, BASE.qBulbosCountByVar, Array.from(selSet), BASE.labels.length);
  const meanDataset = CH.qBulbosVar.data.datasets[varNames.length];
  if (meanDataset) {
    meanDataset.data = sliceByIdx(series, keep);
    meanDataset.hidden = false;
  }
  CH.qBulbosVar.update();
  const meanVal = weightedMean(sliceByIdx(series, keep), sliceByIdx(weights, keep));
  setMetaNumber('q-bulbos-meta', meanVal, 'bulbos/saco', { minimumFractionDigits: 0, maximumFractionDigits: 1 });
}

  function applyDateFilterClient(dFrom, dTo){
    const url = new URL(location.href);
    dFrom ? url.searchParams.set('from', dFrom) : url.searchParams.delete('from');
    dTo   ? url.searchParams.set('to',   dTo)   : url.searchParams.delete('to');
    history.replaceState(null,'', url.toString());

    const keep   = idxRangeByDateISO(BASE.labelsISO,    dFrom, dTo);
    const keepH  = idxRangeByDateISO(BASE.labelsCISO_H, dFrom, dTo);
    const keepO  = idxRangeByDateISO(BASE.labelsCISO_O, dFrom, dTo);
    const hasProdCarrLabels = (BASE.labelsProdCarrISO || []).length > 0;
    const hasProdDescLabels = (BASE.labelsProdDescISO || []).length > 0;
    const keepCarr = idxRangeByDateISO(hasProdCarrLabels ? BASE.labelsProdCarrISO : BASE.labelsISO, dFrom, dTo);
    const keepDesc = idxRangeByDateISO(hasProdDescLabels ? BASE.labelsProdDescISO : BASE.labelsISO, dFrom, dTo);
    window._keepIdx  = keep;
    window._keepIdxH = keepH;
    window._keepIdxO = keepO;
    window._keepIdxCarr = keepCarr;
    window._keepIdxDesc = keepDesc;

    const L   = sliceByIdx(BASE.labels,  keep);
    const LCH = sliceByIdx(BASE.labelsC_H, keepH);
    const LCO = sliceByIdx(BASE.labelsC_O, keepO);
    const LCarr = hasProdCarrLabels ? sliceByIdx(BASE.labelsProdCarr, keepCarr) : L;
    const LCarrISO = hasProdCarrLabels ? sliceByIdx(BASE.labelsProdCarrISO, keepCarr) : sliceByIdx(BASE.labelsISO, keep);
    const LDesc = hasProdDescLabels ? sliceByIdx(BASE.labelsProdDesc, keepDesc) : L;
    const LDescISO = hasProdDescLabels ? sliceByIdx(BASE.labelsProdDescISO, keepDesc) : sliceByIdx(BASE.labelsISO, keep);

    const Sfil = {};
    for (const k of Object.keys(BASE.S)) Sfil[k] = sliceByIdx(BASE.S[k], keep);

    // Recalcular médias gerais do recorte (MINUTOS)
    const mediaPelF   = avgNonNull(Sfil.q6_dia);
    const mediaDefF   = avgNonNull(Sfil.q7_dia);
    const mediaUniF   = avgNonNull(Sfil.q8_dia);
    const mediaDescF  = avgNonNull(Sfil.f_desc_dia);
    const mediaParadaF = avgNonNull(Sfil.p_parada_dia);
    const mediaAprovF = avgNonNull(Sfil.p_aprov_dia);

    // ===== SAFRA KPI (recalcula no recorte) =====
    (function(){
      const metaF = sliceByIdx(BASE.metaSeriesByDay, keep);
      const realF = sliceByIdx(BASE.realSeriesByDay, keep);

      let totMeta = 0, totReal = 0, dMeta=0, dDados=0, dAting=0;

      for (let i=0;i<metaF.length;i++){
        const m = metaF[i], r = realF[i];
        if (m!=null && !Number.isNaN(m) && Number(m)>0) {
          dMeta++;
          if (r!=null && !Number.isNaN(r) && Number(r)>0) {
            dDados++;
            totMeta += Number(m);
            totReal += Number(r);
            const pct = (Number(r)/Number(m))*100;
            if (pct >= 100) dAting++;
          }
        }
      }

      const kpi = (totMeta>0) ? (totReal/totMeta*100) : null;

      // Atualiza textos
      const elKpi   = document.getElementById('kp-ating-safra');
      const elDesc  = document.getElementById('kp-ating-desc');
      const elExtra = document.getElementById('kp-ating-extra');

      const fmtPct = (p)=> Number(p).toLocaleString('pt-BR',{ minimumFractionDigits:0, maximumFractionDigits:2 });
      const fmtNum = (n)=> Number(n).toLocaleString('pt-BR');

      if (elKpi && elDesc && elExtra){
        if (kpi == null) {
          elKpi.textContent = '—';
          elDesc.textContent = 'Sem dados válidos no recorte';
          elExtra.textContent = '—';
        } else {
          elKpi.textContent = `${fmtPct(kpi)}%`;
          elDesc.textContent = `${dAting}/${dDados} dias ≥ 100%`;
          elExtra.textContent = `Realizado: ${fmtNum(totReal)} sacos • Meta: ${fmtNum(totMeta)} sacos`;
        }
      }

// Atualiza o gauge (usa o tamanho do container)
const can = document.getElementById('chartGaugeSafra');

if (can && can._chartInstance && typeof can._chartInstance.destroy === 'function') {
  can._chartInstance.destroy();
}

if (can) {
  const v = kpi == null ? 0 : Math.max(0, Math.min(100, Number(kpi)));
  const g = new Chart(can, {
    type: 'doughnut',
    data: {
      labels: ['Atingido', 'Faltante'],
      datasets: [{
        data: [v, 100 - v],
        backgroundColor: [THEME.g2, hexToRgba(THEME.text, .08)],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
        noData: { text: 'Sem dados no período' }
      }
    }
  });
  can._chartInstance = g;
}

    if (CH.prodAting){
        const labelsF = sliceByIdx(BASE.labels, keep);
        const pctF    = sliceByIdx(BASE.atingPct, keep);

        CH.prodAting.data.labels = labelsF;
        if (CH.prodAting.data.datasets?.[0]) CH.prodAting.data.datasets[0].data = realF;
        if (CH.prodAting.data.datasets?.[1]) CH.prodAting.data.datasets[1].data = metaF;
        if (CH.prodAting.data.datasets?.[2]) CH.prodAting.data.datasets[2].data = pctF;
        CH.prodAting.update();

        setProdMetaSummary(realF, metaF);
      }

      if (CH.prodRomaneio){
        updateProdRomaneioChart();
      }

    // === Comercial HOJE (linhas por caixa) ===
    if (CH.comercial){
      const boxNames = BASE.comBoxNames || [];
      const sel = (window._comercialSelH && window._comercialSelH.length) ? window._comercialSelH : boxNames;

      const LCH = sliceByIdx(BASE.labelsC_H, keepH);
      CH.comercial.data.labels = LCH;

      const selSet = new Set(sel);
      for (let i=0;i<boxNames.length;i++){
        const box = boxNames[i];
        const serieFull = BASE.comHojeBoxSeries?.[box] || [];
        const data = sliceByIdx(serieFull, keepH);
        const dataset = CH.comercial.data.datasets[i];
        dataset.data = data;
        dataset.hidden = !selSet.has(box);
        dataset.label = box;
        dataset.borderColor = colorForCaixa(box);
      }

      const meanLine = buildDailyMeanLine(BASE.comHojeBoxSeries, BASE.comHojeBoxCount, sel, BASE.labelsC_H.length, keepH);

      const meanDataset = CH.comercial.data.datasets[boxNames.length];
      meanDataset.data = meanLine.perDay;
      meanDataset.hidden = false;

      CH.comercial.update();
      setMetaMoney(document.getElementById('com-meta'), meanLine.periodMean);
    }

    // === Comercial ONTEM (linhas por caixa) ===
    if (CH.comercialOntem){
            const boxNames = BASE.comBoxNames || [];
      const sel = (window._comercialSelO && window._comercialSelO.length) ? window._comercialSelO : boxNames;

      const LCO = sliceByIdx(BASE.labelsC_O, keepO);
      CH.comercialOntem.data.labels = LCO;

      const selSet = new Set(sel);
      for (let i=0;i<boxNames.length;i++){
        const box = boxNames[i];
        const serieFull = BASE.comOntemBoxSeries?.[box] || [];
        const data = sliceByIdx(serieFull, keepO);
        const dataset = CH.comercialOntem.data.datasets[i];
        dataset.data = data;
        dataset.hidden = !selSet.has(box);
        dataset.label = box;
        dataset.borderColor = colorForCaixa(box);
      }

      const meanLine = buildDailyMeanLine(BASE.comOntemBoxSeries, BASE.comOntemBoxCount, sel, BASE.labelsC_O.length, keepO);

      const meanDataset = CH.comercialOntem.data.datasets[boxNames.length];
      meanDataset.data = meanLine.perDay;
      meanDataset.hidden = false;
      CH.comercialOntem.update();
      setMetaMoney(document.getElementById('com-ontem-meta'), meanLine.periodMean);
    }

    // ===== Logística (por veículo + médias individuais) – HORAS
    if (CH.logistica){
      CH.logistica.data.labels = L;
      const { datasets, meanMap } = buildTypeDatasets(BASE.typesLogSel || [], BASE.logTiposSel || {}, keep, L, colorForLog, {}, 'Média', (t)=>t, 'running');
      logMeanMap = meanMap;
      CH.logistica.data.datasets = datasets;

      CH.logistica.update();
      setTypeMetaHours('log-meta', meanMap);
    }

    // Qualidade
    if (CH.qPelada){
      CH.qPelada.data.labels = L;
      CH.qPelada.data.datasets[0].data = Sfil.q6_dia;
      CH.qPelada.data.datasets[1].data = new Array(L.length).fill(mediaPelF);
      CH.qPelada.update();
      setMetaPercent('q-meta-pelada', mediaPelF);
    }
    if (CH.qDefeitos){
      CH.qDefeitos.data.labels = L;
      CH.qDefeitos.data.datasets[0].data = Sfil.q7_dia;
      CH.qDefeitos.data.datasets[1].data = new Array(L.length).fill(mediaDefF);
      CH.qDefeitos.update();
      setMetaPercent('q-meta-defeitos', mediaDefF);
    }
    if (CH.qUniform){
      CH.qUniform.data.labels = L;
      CH.qUniform.data.datasets[0].data = Sfil.q8_dia;
      CH.qUniform.data.datasets[1].data = new Array(L.length).fill(mediaUniF);
      CH.qUniform.update();
      setMetaPercent('q-meta-uniform', mediaUniF);
    }

    // Produção Sacos
    if (CH.qPmbVar){
      updateQPmbChart();
    }
    if (CH.qBulbosVar){
      updateQBulbosChart();
    }

    if (CH.prodSacos){
      CH.prodSacos.data.labels = L;
      CH.prodSacos.data.datasets[0].data = Sfil.p16_dia;
      CH.prodSacos.data.datasets[1].data = Sfil.p15_dia;
      CH.prodSacos.update();
    }

    // Produção Carregamento — HORAS
    if (CH.prodCarreg){
      CH.prodCarreg.data.labels = LCarr;
      const prodCarrByDate = projectTypeSeriesByDate(
        BASE.prodCarrTipos || {},
        hasProdCarrLabels ? (BASE.labelsProdCarrISO || []) : (BASE.labelsISO || []),
        LCarrISO
      );
      const { datasets, meanMap } = buildTypeDatasets(
        BASE.typesProd || [],
        prodCarrByDate,
        null,
        LCarr,
        (t) => colorForType(t, false, false),
        {},
        'Média',
        (t)=>t,
        'running'
      );
      prodCarrMeanMap = meanMap;
      CH.prodCarreg.data.datasets = datasets;
      CH.prodCarreg.update();
      setTypeMetaHours('prod-carr-meta', meanMap);
    }

    // Produção Descarregamento — HORAS
    if (CH.prodDesc){
      CH.prodDesc.data.labels = LDesc;
      const { datasets, meanMap } = buildTypeDatasets(
        BASE.typesProdDesc || [],
        BASE.prodDescTipos || {},
        keepDesc,
        LDesc,
        (t) => colorForType(t, false, true),
        {},
        'Média',
        (t)=>t,
        'running'
      );
      prodDescMeanMap = meanMap;
      CH.prodDesc.data.datasets = datasets;
      CH.prodDesc.update();
      setTypeMetaHours('prod-desc-meta', meanMap);
    }

    if (CH.prodParada){
      CH.prodParada.data.labels = L;
      CH.prodParada.data.datasets[0].data = seriesMinToHours(Sfil.p_parada_dia || []);
      const meanHours = mediaParadaF == null ? null : mediaParadaF / 60;
      CH.prodParada.data.datasets[1].data = new Array(L.length).fill(meanHours);
      CH.prodParada.update();
      setMetaHours('prod-parada-meta', mediaParadaF);
    }

    // Produção Aproveitamento
    if (CH.prodAprov){
      CH.prodAprov.data.labels = L;
      CH.prodAprov.data.datasets[0].data = Sfil.p_aprov_dia;
      CH.prodAprov.data.datasets[1].data = new Array(L.length).fill(mediaAprovF);
      CH.prodAprov.update();
      setMetaPercent('prod-aprov-meta', mediaAprovF);
    }

    // ===== Fazenda Carregamento — HORAS (DINÂMICO POR TIPO + média diária)
    if (CH.fazCarr){
      CH.fazCarr.data.labels = L;
      const { datasets, meanMap } = buildTypeDatasets(
        BASE.typesFaz || [],
        BASE.fazCarrTipos || {},
        keep,
        L,
        (t) => colorForType(t, true),
        { borderWidth:3 },
        'Média',
        (t) => `${t} (total/dia)`,
        'running'
      );

      fazCarrMeanMap = meanMap;
      CH.fazCarr.data.datasets = datasets;
      CH.fazCarr.update();

      setTypeMetaHours('faz-carreg-meta', meanMap);
    }

    // Pessoas
    if (CH.fazPessoas){
      CH.fazPessoas.data.labels = L;
      const f17 = Sfil.f17_dia;
      const m17 = avgNonNull(f17);
      CH.fazPessoas.data.datasets[0].data = f17;
      CH.fazPessoas.data.datasets[1].data = new Array(L.length).fill(m17);
      CH.fazPessoas.update();
      const el = document.getElementById('faz-pessoas-meta');
      if (el) el.textContent = (m17==null?'—':`• Média no período: ${Number(m17).toLocaleString('pt-BR',{ maximumFractionDigits:2 })}`);
    }

    // Colhedora
    if (CH.fazColhedora){
      CH.fazColhedora.data.labels = L;
      const f19 = Sfil.f19_dia;
      const m19 = avgNonNull(f19);
      CH.fazColhedora.data.datasets[0].data = f19;
      CH.fazColhedora.data.datasets[1].data = new Array(L.length).fill(m19);
      CH.fazColhedora.update();
      const el = document.getElementById('faz-colhedora-meta');
      if (el) el.textContent = (m19==null?'—':`• Média no período: ${Number(m19).toLocaleString('pt-BR',{ maximumFractionDigits:2 })}`);
    }

    // F18
    if (CH.f18){
      CH.f18.data.labels = L;
      let idx = 0;
      for (const vn of BASE.f18VarNames){
        const serie = sliceByIdx(BASE.f18SeriesByVar[vn] || [], keep);
        CH.f18.data.datasets[idx].data = serie;
        idx++;
      }
      const totalF = sliceByIdx(BASE.f18TotalSeries, keep);
      CH.f18.data.datasets[idx].data = totalF;
      const mean = avgNonNull(totalF);
      CH.f18.data.datasets[idx+1].data = new Array(L.length).fill(mean);
      CH.f18.update();
    }
   })(); // fecha a IIFE do bloco SAFRA KPI
}
  // ===== Botões / URL state (SEM RELOAD)
  const gridCharts = document.getElementById('gridCharts');
  function visibleCardsCount(){
    let n = 0;
    CATALOG.forEach(s => { const el = document.getElementById(s.id); if (el && el.style.display !== 'none') n++; });
    return n;
  }
  function updateGridCols(){
    const isFS = !!document.fullscreenElement;
    if (!isFS){ gridCharts.style.gridTemplateColumns = ''; return; }
    const n = Math.max(1, visibleCardsCount());
    let cols = Math.ceil(Math.sqrt(n));
    cols = Math.max(2, Math.min(4, cols));
    gridCharts.style.gridTemplateColumns = `repeat(${cols}, minmax(360px, 1fr))`;
  }
  document.addEventListener('fullscreenchange', updateGridCols);
  window.addEventListener('resize', updateGridCols);

  function updateCountBadgeSelected(){
    const count = selectedSecs?.size || 0;
    const val = (count===0) ? CATALOG.length : count;
    if (btnGraphsBadge)   btnGraphsBadge.textContent   = String(val);
    if (btnGraphsBadgeFS) btnGraphsBadgeFS.textContent = String(val);
  }

  const graphsModalEl = document.getElementById('graphsModal');
  document.getElementById('modalApply')?.addEventListener('click', ()=>{
    try{
      const tmpSel = graphsModalEl.dataset.tmpSelection
        ? new Set(JSON.parse(graphsModalEl.dataset.tmpSelection))
        : selectedSecs;
      selectedSecs = new Set([...tmpSel].filter(id => ALLOWED_SEC_IDS.includes(id)));
    }catch(e){}

    if (!selectedSecs || selectedSecs.size===0) {
      selectedSecs = new Set(CATALOG.map(s=>s.id));
    }

    applySecFilter();
    pushSecToQuery();
    updateCountBadgeSelected();

    const de  = document.getElementById('modalFrom').value || '';
    const ate = document.getElementById('modalTo').value   || '';

    const headFrom = document.getElementById('headFrom');
    const headTo   = document.getElementById('headTo');
    if (headFrom) headFrom.value = de;
    if (headTo)   headTo.value   = ate;

    applyDateFilterClient(de, ate);
    graphsModalEl.classList.add('hidden');
  });

  // Estado inicial
  function applySecFilterInit(){
    if (!selectedSecs || selectedSecs.size===0) selectedSecs = new Set(CATALOG.map(s=>s.id));
    applySecFilter();
    updateCountBadgeSelected();
  }
  applySecFilterInit();

  // ===== Chart.js base
  const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const hexToRgba = (hex, a=1) => {
    const h = hex.replace('#','');
    const bigint = parseInt(h,16);
    const r = (h.length===3) ? ((bigint>>8)&0xF)*17 : (bigint>>16)&255;
    const g = (h.length===3) ? ((bigint>>4)&0xF)*17 : (bigint>>8)&255;
    const b = (h.length===3) ? (bigint&0xF)*17 : (bigint)&255;
    return `rgba(${r},${g},${b},${a})`;
  };

  Chart.defaults.color = THEME.text;
  Chart.defaults.borderColor = hexToRgba('#000', .08);
  Chart.defaults.elements.line.borderWidth = 2;
  Chart.defaults.elements.bar.borderRadius = 8;
  Chart.defaults.plugins.legend.position = 'bottom';
  Chart.defaults.animation = { duration: prefersReducedMotion ? 0 : 700, easing: 'easeOutCubic' };
  Chart.defaults.animations = {
    x: { type: 'number', duration: prefersReducedMotion ? 0 : 500, easing: 'easeOutCubic' },
    y: { type: 'number', duration: prefersReducedMotion ? 0 : 700, easing: 'easeOutCubic' }
  };
  Chart.defaults.transitions = {
    show: { animations: { x: { from: NaN }, y: { from: NaN, duration: prefersReducedMotion ? 0 : 400 } } },
    hide: { animations: { y: { to: NaN, duration: prefersReducedMotion ? 0 : 300 } } }
  };

  const noDataPlugin = {
    id: 'noData',
    afterDraw(chart, args, opts){
      const datasets = chart?.data?.datasets || [];
      const hasAny = datasets.some(ds => {
        const arr = Array.isArray(ds?.data) ? ds.data : [];
        // considera qualquer número válido (inclui 0)
        return arr.some(v => v != null && !Number.isNaN(Number(v)));
      });
      if (hasAny) return;

      const {ctx, chartArea} = chart;
      if (!ctx || !chartArea) return;
      const msg = (opts && opts.text) || 'Sem dados no período';
      ctx.save();
      ctx.fillStyle = 'rgba(0,0,0,0.5)';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '600 14px Nunito, system-ui, sans-serif';
      const x = (chartArea.left + chartArea.right)/2;
      const y = (chartArea.top + chartArea.bottom)/2;
      ctx.fillText(msg, x, y);
      ctx.restore();
    }
  };

Chart.register(noDataPlugin);

  const lastIndexOfData = (arr)=>{ for(let i=arr.length-1;i>=0;i--){ if(arr[i]!=null) return i; } return -1; };

  const mkLine = (label, data, color, yAxisID='y', extras={}) => {
    const li = lastIndexOfData(data||[]);
    return {
      type:'line',
      label, data, yAxisID,
      tension:.35, fill:false, spanGaps:true,
      borderColor: color,
      backgroundColor: hexToRgba(color, .18),
      borderDash: extras.borderDash ?? [],
      borderWidth: extras.borderWidth ?? 2.5,
      pointRadius: (ctx)=> (ctx?.dataIndex===li ? (extras.pointRadiusLast ?? 4) : (extras.pointRadius ?? 2)),
      pointHoverRadius: (ctx)=> (ctx?.dataIndex===li ? (extras.pointHoverRadiusLast ?? 6) : (extras.pointHoverRadius ?? 4)),
    };
  };
  const mkBar  = (label, data, color, yAxisID='y') => ({
    type:'bar',
    label, data, yAxisID,
    borderWidth:1,
    borderColor: color,
    backgroundColor: hexToRgba(color, .85),
  });

  const baseOpts = (beginAtZero=true) => ({
    responsive:true,
    layout:{ padding:{ top:8, right:30 } },
    plugins:{
      legend:{ position:'bottom', labels:{ color: THEME.text, boxWidth:12 } },
      tooltip: { callbacks: { label: (ctx)=>{
        const v = ctx.parsed.y;
        const base = (v==null?'-':v.toLocaleString('pt-BR',{ maximumFractionDigits:3 }));
        return `${ctx.dataset.label}: ${base}`;
      }}},
      noData: { text: 'Sem dados no período' }
    },
    scales:{ x:{ ticks:{ color: hexToRgba(THEME.text,.7) } }, y:{ beginAtZero, ticks:{ color: hexToRgba(THEME.text,.7) } } }
  });

  // ===== Opções para HORAS (tooltip HH:MM)
  const hoursOpts = {
    ...baseOpts(true),
    plugins: {
      ...baseOpts(true).plugins,
      tooltip:{ callbacks:{ label:(ctx)=>{
        const vH = ctx.parsed.y;
        if (vH==null) return `${ctx.dataset.label}: -`;
        const min = Number(vH)*60;
        const hhmm = minutesToHHMM(min);
        return `${ctx.dataset.label}: ${vH.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 })} h${hhmm?` (${hhmm})`:''}`;
      }}}
    },
    scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Horas' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
  };

  const typePalette = ['#0072B2','#E69F00','#D55E00','#CC79A7','#56B4E9','#009E73','#F0E442','#000000','#8A2BE2','#FF7F50','#3CB371','#DA70D6'];
  const VAR_PALETTE_NAMES = Array.from(new Set([
    ...(BASE.qPmbVarNames || []),
    ...(BASE.qBulbosVarNames || []),
    ...(BASE.f18VarNames || []),
  ]));
  const colorForType = (name, isFaz=false, isDesc=false) => {
    const baseList = isFaz ? typesFaz : (isDesc ? typesProdDesc : typesProd);
    const idx = baseList.indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };
  const colorForLog = (name) => {
    const idx = (BASE.typesLogSel || []).indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };
  const colorForVar = (name) => {
    const idx = VAR_PALETTE_NAMES.indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };
    const colorForCaixa = (name) => {
    const idx = (comBoxNames || []).indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };
  const colorForRomaneioBox = (name) => {
    const keys = BASE.prodRomBoxKeys || [];
    const idx = keys.indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };

// ===== Comercial HOJE (linha diária por caixa + média do recorte) =====
(function(){
  const el = document.getElementById('chartComercialMedia');
  if (!el) return;

    const boxNames = BASE.comBoxNames || [];
  const datasets = boxNames.map(box => (
    { ...mkLine(box, new Array(BASE.labelsC_H.length).fill(null), colorForCaixa(box), 'y', { borderWidth:3 }) }
  ));
  datasets.push(mkLine('Média selecionada (R$/SC)', new Array(BASE.labelsC_H.length).fill(null), THEME.g3, 'y', { pointRadius:3, pointHoverRadius:5, pointRadiusLast:5, pointHoverRadiusLast:7, borderDash:[6,4], borderWidth:3 }));

  CH.comercial = new Chart(el, {
    data: { labels: BASE.labelsC_H, datasets },
    options: {
      ...baseOpts(true),
      plugins:{
        ...baseOpts(true).plugins,
        tooltip:{ callbacks:{ label:(ctx)=>{
          const v = ctx.parsed.y;
          const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
          return `${ctx.dataset.label}: R$ ${txt}/SC`;
        }}}
      },
      scales: {
        y:  { beginAtZero:true, position:'left',  title:{ display:true, text:'R$/SC' } }
      }
    }
  });

    const updateHoje = () => {
    const selected = (window._comercialSelH && window._comercialSelH.length) ? window._comercialSelH : boxNames;
    const varSel = (window._comercialVarSelH && window._comercialVarSelH.length) ? window._comercialVarSelH : null;
    const { seriesMap, countMap } = aggregateVarietySeries('H', varSel);

    const idx = (window._keepIdxH && window._keepIdxH.length)
      ? window._keepIdxH
      : BASE.labelsCISO_H.map((_, i) => i);

    const labels = sliceByIdx(BASE.labelsC_H, idx);
    CH.comercial.data.labels = labels;

    const selSet = new Set(selected);
    for (let i=0;i<boxNames.length;i++){
      const box = boxNames[i];
      const serieFull = seriesMap?.[box] || [];
      const data = sliceByIdx(serieFull, idx);
      const dataset = CH.comercial.data.datasets[i];
      dataset.data = data;
      dataset.hidden = !selSet.has(box);
      dataset.label = box;
      dataset.borderColor = colorForCaixa(box);
    }

    const meanLine = buildDailyMeanLine(seriesMap, countMap, selected, BASE.labelsC_H.length, idx);

    const meanDataset = CH.comercial.data.datasets[boxNames.length];
    meanDataset.data = meanLine.perDay;
    meanDataset.hidden = false;

    CH.comercial.update();
    setMetaMoney(document.getElementById('com-meta'), meanLine.periodMean);
  };

  const allVariedadesH = BASE.comVarietyNames || [];
  window._comercialVarSelH = [...allVariedadesH];
  if (document.getElementById('comercialVarietyPicker') && allVariedadesH.length) {
    buildVarPicker('comercialVarietyPicker', allVariedadesH, allVariedadesH, (sel) => {
      window._comercialVarSelH = (sel && sel.length) ? sel : [...allVariedadesH];
      updateHoje();
    });
  }

  buildVarPicker('comercialVarPicker', boxNames, boxNames, (sel) => {
    window._comercialSelH = (sel && sel.length) ? sel : boxNames;
    updateHoje();
  });
})();

  // ===== Comercial ONTEM (inicia ponderado) =====
  // ===== Comercial ONTEM (linha diária + média ponderada R$/SC) =====
(function(){
  const el = document.getElementById('chartComercialOntem');
  if (!el) return;

  const boxNames = BASE.comBoxNames || [];
  const datasets = boxNames.map(box => (
    { ...mkLine(box, new Array(BASE.labelsC_O.length).fill(null), colorForCaixa(box), 'y', { borderWidth:3 }) }
  ));
  datasets.push(mkLine('Média selecionada (R$/SC)', new Array(BASE.labelsC_O.length).fill(null), THEME.g3, 'y', { pointRadius:3, pointHoverRadius:5, pointRadiusLast:5, pointHoverRadiusLast:7, borderDash:[6,4], borderWidth:3 }));

  CH.comercialOntem = new Chart(el, {
    data: { labels: BASE.labelsC_O, datasets },
    options: {
      ...baseOpts(true),
      plugins:{
        ...baseOpts(true).plugins,
        tooltip:{ callbacks:{ label:(ctx)=>{
          const v = ctx.parsed.y;
          const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
          return `${ctx.dataset.label}: R$ ${txt}/SC`;
        }}}
      },
      scales: {
        y:  { beginAtZero:true, position:'left',  title:{ display:true, text:'R$/SC' } }
      }
    }
  });

    const updateOntem = () => {
    const selected = (window._comercialSelO && window._comercialSelO.length) ? window._comercialSelO : boxNames;
    const varSel = (window._comercialVarSelO && window._comercialVarSelO.length) ? window._comercialVarSelO : null;
    const { seriesMap, countMap } = aggregateVarietySeries('O', varSel);

    const idx = (window._keepIdxO && window._keepIdxO.length)
      ? window._keepIdxO
      : BASE.labelsCISO_O.map((_, i) => i);

    const labels = sliceByIdx(BASE.labelsC_O, idx);
    CH.comercialOntem.data.labels = labels;

    const selSet = new Set(selected);
    for (let i=0;i<boxNames.length;i++){
      const box = boxNames[i];
      const serieFull = seriesMap?.[box] || [];
      const data = sliceByIdx(serieFull, idx);
      const dataset = CH.comercialOntem.data.datasets[i];
      dataset.data = data;
      dataset.hidden = !selSet.has(box);
      dataset.label = box;
      dataset.borderColor = colorForCaixa(box);
    }

    const meanLine = buildDailyMeanLine(seriesMap, countMap, selected, BASE.labelsC_O.length, idx);

    const meanDataset = CH.comercialOntem.data.datasets[boxNames.length];
    meanDataset.data = meanLine.perDay;
    meanDataset.hidden = false;

    CH.comercialOntem.update();
    setMetaMoney(document.getElementById('com-ontem-meta'), meanLine.periodMean);
      };

  const allVariedadesO = BASE.comVarietyNames || [];
  window._comercialVarSelO = [...allVariedadesO];
  if (document.getElementById('comercialOntemVarietyPicker') && allVariedadesO.length) {
    buildVarPicker('comercialOntemVarietyPicker', allVariedadesO, allVariedadesO, (sel) => {
      window._comercialVarSelO = (sel && sel.length) ? sel : [...allVariedadesO];
      updateOntem();
    });
  }
  // ===== Produção: Romaneio por caixa
  (function(){
    const el = document.getElementById('chartProdRomaneio');
    if (!el) return;

    const boxKeys = BASE.prodRomBoxKeys || [];
    const datasets = boxKeys.map(boxKey => mkLine(
      BASE.prodRomBoxLabels?.[boxKey] || boxKey,
      new Array(labels.length).fill(null),
      colorForRomaneioBox(boxKey),
      'y',
      { borderWidth:3 }
    ));

    CH.prodRomaneio = new Chart(el, {
      data:{ labels, datasets },
      options:{
        ...baseOpts(true),
        plugins:{ ...baseOpts(true).plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } },
        scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Caixas' } } }
      }
    });

    window._prodRomVarSel = [...(BASE.prodRomVarietyNames || [])];
    if (document.getElementById('prodRomaneioVarietyPicker') && (BASE.prodRomVarietyNames || []).length){
      buildVarPicker('prodRomaneioVarietyPicker', BASE.prodRomVarietyNames, BASE.prodRomVarietyNames, (sel)=>{
        window._prodRomVarSel = (sel && sel.length) ? sel : [...(BASE.prodRomVarietyNames || [])];
        updateProdRomaneioChart();
      });
    }

    updateProdRomaneioChart();
  })();

  buildVarPicker('comercialOntemVarPicker', boxNames, boxNames, (sel) => {
    window._comercialSelO = (sel && sel.length) ? sel : boxNames;
    updateOntem();
  });
})();

  // ===== LOGÍSTICA (por veículo + médias individuais) – HORAS
  (function(){
    const el = document.getElementById('chartLogistica');
    if (!el) return;
    CH.logistica = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });

      const { datasets, meanMap } = buildTypeDatasets(
      BASE.typesLogSel || [],
      BASE.logTiposSel || {},
      null,
      labels,
      colorForLog,
      {},
      'Média',
      (t)=>t,
      'running'
    );
    logMeanMap = meanMap;
    CH.logistica.data.datasets = datasets; CH.logistica.update();

    setTypeMetaHours('log-meta', meanMap);
  })();

  // ===== Qualidade (3 gráficos)
  const mkQualOpts = () => ({
    ...baseOpts(true),
    plugins:{
      ...baseOpts(true).plugins,
      tooltip:{ callbacks:{ label:(ctx)=>{
        const v = ctx.parsed.y;
        const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 }));
        return `${ctx.dataset.label}: ${txt} %`;
      }}}
    },
    scales:{ y:{ beginAtZero:true, suggestedMax:100, title:{ display:true, text:'%' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
  });

  (function(){
    const el = document.getElementById('chartQPelada');
    if (!el) return;
    CH.qPelada = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Pelada (%)',           S.q6_dia, THEME.yellow),
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaPelada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options: mkQualOpts()
    });
    setMetaPercent('q-meta-pelada', <?php echo json_encode($mediaPelada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  (function(){
    const el = document.getElementById('chartQDefeitos');
    if (!el) return;
    CH.qDefeitos = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Defeitos (%)',         S.q7_dia, THEME.red),
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaDefeitos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options: mkQualOpts()
    });
    setMetaPercent('q-meta-defeitos', <?php echo json_encode($mediaDefeitos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  (function(){
    const el = document.getElementById('chartQUniform');
    if (!el) return;
    CH.qUniform = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Uniformidade (%)',     S.q8_dia, THEME.g3),
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaUniform, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options: mkQualOpts()
    });
    setMetaPercent('q-meta-uniform', <?php echo json_encode($mediaUniform, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  (function(){
    const el = document.getElementById('chartQPmbVar');
    if (!el) return;

    const varNames = BASE.qPmbVarNames || [];
    const datasets = varNames.map((vn) => mkLine(vn, new Array(labels.length).fill(null), colorForVar(vn), 'y', { borderWidth:3 }));
    datasets.push(mkLine('Média selecionada', new Array(labels.length).fill(null), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));

    CH.qPmbVar = new Chart(el, {
      data:{ labels, datasets },
      options:{
        ...baseOpts(true),
        plugins:{
          ...baseOpts(true).plugins,
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':Number(v).toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
            return `${ctx.dataset.label}: ${txt} kg`;
          }}}
        },
        scales:{ y:{ beginAtZero:true, title:{ display:true, text:'kg' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
      }
    });

    window._qPmbVarSel = [...varNames];
    if (document.getElementById('qPmbVarPicker') && varNames.length){
      buildVarPicker('qPmbVarPicker', varNames, varNames, (sel)=>{
        window._qPmbVarSel = (sel && sel.length) ? sel : [...varNames];
        updateQPmbChart();
      });
    }
    updateQPmbChart();
  })();

  (function(){
    const el = document.getElementById('chartQBulbosVar');
    if (!el) return;

    const varNames = BASE.qBulbosVarNames || [];
    const datasets = varNames.map((vn) => mkLine(vn, new Array(labels.length).fill(null), colorForVar(vn), 'y', { borderWidth:3 }));
    datasets.push(mkLine('Média selecionada', new Array(labels.length).fill(null), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));

    CH.qBulbosVar = new Chart(el, {
      data:{ labels, datasets },
      options:{
        ...baseOpts(true),
        plugins:{
          ...baseOpts(true).plugins,
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':Number(v).toLocaleString('pt-BR',{ minimumFractionDigits:0, maximumFractionDigits:1 }));
            return `${ctx.dataset.label}: ${txt} bulbos/saco`;
          }}}
        },
        scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Bulbos/saco' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
      }
    });

    window._qBulbosVarSel = [...varNames];
    if (document.getElementById('qBulbosVarPicker') && varNames.length){
      buildVarPicker('qBulbosVarPicker', varNames, varNames, (sel)=>{
        window._qBulbosVarSel = (sel && sel.length) ? sel : [...varNames];
        updateQBulbosChart();
      });
    }
    updateQBulbosChart();
  })();
  // ===== Produção: Sacos
  (function(){
    const el = document.getElementById('chartProdSacos');
    if (!el) return;
    CH.prodSacos = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Sacos por colaborador',      S.p16_dia, THEME.yellow, 'y'),
        mkBar ('Sacos beneficiados (dia)',   S.p15_dia, THEME.g2,     'y1'),
      ]},
      options:{
        responsive:true,
        plugins:{
          legend:{ position:'bottom' },
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ maximumFractionDigits:2 }));
            return `${ctx.dataset.label}: ${txt}`;
          }}}
        },
        scales:{
          y1 :{ beginAtZero:true, title:{ display:true, text:'Sacos (total do dia)' } },
          y:{ beginAtZero:true, position:'right', grid:{ drawOnChartArea:false }, title:{ display:true, text:'Sacos/colaborador' } }
        }
      }
    });
  })();

  // ===== Produção: Meta × Sacos beneficiados/dia + percentual
  (function(){
    const el = document.getElementById('chartProdAting');
    if (!el) return;

    const metaSeries = BASE.metaSeriesByDay || [];
    const realSeries = BASE.realSeriesByDay || [];
    const pctSeries  = BASE.atingPct || [];

    const hasSeries = [metaSeries, realSeries].some(arr => (arr || []).some(v => v != null && !Number.isNaN(Number(v))));

    if (!hasSeries) {
      CH.prodAting = new Chart(el, {
        data: { labels, datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { display:false }, noData: { text:'Sem dados no período' } },
          scales: { y:{ beginAtZero:true, title:{ display:true, text:'Sacos beneficiados/dia' } } }
        }
      });
      setProdMetaSummary([], []);
      return;
    }

    CH.prodAting = new Chart(el, {
      data: {
        labels,
        datasets: [
          mkBar('Sacos beneficiados/dia', realSeries, THEME.g2, 'y'),
          mkLine('Meta do dia (sacos)', metaSeries, THEME.g1, 'y', { borderWidth:3 }),
          mkLine('Atingimento (%)', pctSeries, THEME.yellow, 'y1', {
            borderDash:[6,4],
            borderWidth:2,
            pointRadius:0,
            pointHoverRadius:0,
            pointRadiusLast:3,
            pointHoverRadiusLast:4
          })
        ]
      },
      options: {
        responsive: true,
        interaction:{ mode:'index', intersect:false },
        plugins: {
          legend: { position:'bottom' },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const v = ctx.parsed.y;
                if (v == null || Number.isNaN(Number(v))) return `${ctx.dataset.label}: -`;
                const axis = ctx.dataset.yAxisID;
                const suffix = axis === 'y1' ? ' %' : ' sacos';
                const digits = axis === 'y1'
                  ? { minimumFractionDigits:0, maximumFractionDigits:2 }
                  : { maximumFractionDigits:0 };
                const txt = Number(v).toLocaleString('pt-BR', digits);
                return `${ctx.dataset.label}: ${txt}${suffix}`;
              }
            }
          },
          noData:{ text:'Sem dados no período' }
        },
        scales: {
          y:  { beginAtZero:true, title:{ display:true, text:'Sacos beneficiados/dia' } },
          y1: { beginAtZero:true, suggestedMax:120, position:'right', grid:{ drawOnChartArea:false }, title:{ display:true, text:'Atingimento (%)' } }
        }
      }
    });

    setProdMetaSummary(realSeries, metaSeries);
  })();

  // ===== Produção: Carregamento – HORAS
  (function(){
    const el = document.getElementById('chartProdCarreg');
    if (!el) return;
    const lblCarr = (labelsProdCarr && labelsProdCarr.length) ? labelsProdCarr : labels;
    const lblCarrISO = (labelsProdCarrISO && labelsProdCarrISO.length) ? labelsProdCarrISO : labelsISO;
    CH.prodCarreg = new Chart(el, {
      data:{ labels: lblCarr, datasets:[] },
      options:{
        ...hoursOpts,
        plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } },
        scales:{
          ...hoursOpts.scales,
          x:{
            ...(hoursOpts.scales?.x || {}),
            type:'category',
            ticks:{
              ...(hoursOpts.scales?.x?.ticks || {}),
              autoSkip:false,
              maxRotation:0,
              minRotation:0,
              callback:function(value, idx){
                const labs = this?.chart?.data?.labels;
                return (labs && labs[idx] != null) ? labs[idx] : value;
              }
            }
          }
        }
      }
    });
    const prodCarrByDate = projectTypeSeriesByDate(
      BASE.prodCarrTipos || {},
      (labelsProdCarrISO && labelsProdCarrISO.length) ? (BASE.labelsProdCarrISO || []) : (BASE.labelsISO || []),
      lblCarrISO
    );
    const { datasets, meanMap } = buildTypeDatasets(
      BASE.typesProd || [],
      prodCarrByDate,
      null,
      lblCarr,
      (t) => colorForType(t, false, false),
      {},
      'Média',
      (t)=>t,
      'running'
    );
    prodCarrMeanMap = meanMap;
    CH.prodCarreg.data.datasets = datasets; CH.prodCarreg.update();
    setTypeMetaHours('prod-carr-meta', meanMap);
  })();

  // ===== Produção: Descarregamento – HORAS
  (function(){
    const el = document.getElementById('chartProdDesc');
    if (!el) return;
    const lblDesc = (labelsProdDesc && labelsProdDesc.length) ? labelsProdDesc : labels;
    CH.prodDesc = new Chart(el, {
      data:{ labels: lblDesc, datasets:[] },
      options:{
        ...hoursOpts,
        plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } },
        scales:{
          ...hoursOpts.scales,
          x:{
            ...(hoursOpts.scales?.x || {}),
            type:'category',
            ticks:{
              ...(hoursOpts.scales?.x?.ticks || {}),
              autoSkip:false,
              maxRotation:0,
              minRotation:0,
              callback:(value, idx)=> (lblDesc?.[idx] ?? value)
            }
          }
        }
      }
    });
    const { datasets, meanMap } = buildTypeDatasets(
      BASE.typesProdDesc || [],
      BASE.prodDescTipos || {},
      null,
      lblDesc,
      (t) => colorForType(t, false, true),
      {},
      'Média',
      (t)=>t,
      'running'
    );
        prodDescMeanMap = meanMap;
    CH.prodDesc.data.datasets = datasets; CH.prodDesc.update();
    setTypeMetaHours('prod-desc-meta', meanMap);
  })();

  // ===== Produção: Máquina parada – HORAS
  (function(){
    const el = document.getElementById('chartProdParada');
    if (!el) return;
    const mediaHoras = <?php echo json_encode(($mediaParada !== null) ? $mediaParada/60 : null, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
    CH.prodParada = new Chart(el, {
      data:{
        labels,
        datasets:[
          mkBar('Máquina parada (h)', seriesMinToHours(S.p_parada_dia || []), THEME.red, 'y'),
          mkLine('Média no período (h)', new Array(labels.length).fill(mediaHoras), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 })
        ]
      },
      options: hoursOpts
    });
    setMetaHours('prod-parada-meta', <?php echo json_encode($mediaParada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  // ===== Produção: Aproveitamento
  (function(){
    setMetaPercent('prod-aprov-meta', <?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);

    const el = document.getElementById('chartProdAprov');
    if (!el) return;
    CH.prodAprov = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Aproveitamento (%)', S.p_aprov_dia, THEME.g2, 'y'),
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options: {
        ...baseOpts(true),
        plugins:{
          ...baseOpts(true).plugins,
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 }));
            return `${ctx.dataset.label}: ${txt} %`;
          }}}
        },
        scales:{ y:{ beginAtZero:true, suggestedMax:100, title:{ display:true, text:'%' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
      }
    });
  })();

  // ===== Fazenda Carregamento — HORAS (DINÂMICO)
  (function(){
    const el = document.getElementById('chartFazendaCarreg');
    if (!el) return;

    const { datasets, meanMap } = buildTypeDatasets(
      BASE.typesFaz || [],
      BASE.fazCarrTipos || {},
      null,
      labels,
      (t) => colorForType(t, true),
      { borderWidth:3 },
      'Média',
      (t) => `${t} (total/dia)`,
      'running'
    );

    fazCarrMeanMap = meanMap;
    CH.fazCarr = new Chart(el, {
      data:{ labels, datasets },
      options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } }
    });

    setTypeMetaHours('faz-carreg-meta', meanMap);
  })();

  // ===== Pessoas (F17)
  (function(){
    const el = document.getElementById('chartFazendaPessoas');
    if (!el) return;
    CH.fazPessoas = new Chart(el, {
      data:{ labels, datasets:[
        mkBar ('Pessoas/dia', S.f17_dia, THEME.g3, 'y'),
        mkLine('Média no período', new Array(labels.length).fill(mediaF17), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options:{
        responsive:true,
        plugins:{ legend:{ position:'bottom' }, noData:{ text:'Sem dados no período' } },
        scales:{ y :{ beginAtZero:true, title:{ display:true, text:'Pessoas' } } }
      }
    });
    const elMeta = document.getElementById('faz-pessoas-meta');
    if (elMeta) elMeta.textContent = (mediaF17==null?'—':`• Média no período: ${Number(mediaF17).toLocaleString('pt-BR',{ maximumFractionDigits:2 })}`);
  })();

  // ===== Colhedora (F19)
  (function(){
    const el = document.getElementById('chartFazendaColhedora');
    if (!el) return;
    CH.fazColhedora = new Chart(el, {
      data:{ labels, datasets:[
        mkBar ('Colhedora/dia', S.f19_dia, THEME.g2, 'y'),
        mkLine('Média no período', new Array(labels.length).fill(mediaF19), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ),
      ]},
      options:{
        responsive:true,
        plugins:{ legend:{ position:'bottom' }, noData:{ text:'Sem dados no período' } },
        scales:{ y :{ beginAtZero:true, title:{ display:true, text:'Qtd' } } }
      }
    });
    const elMeta = document.getElementById('faz-colhedora-meta');
    if (elMeta) elMeta.textContent = (mediaF19==null?'—':`• Média no período: ${Number(mediaF19).toLocaleString('pt-BR',{ maximumFractionDigits:2 })}`);
  })();

  // ===== F18 Big bag por Variedade (linhas)
  (function(){
    const el = document.getElementById('chartPie');
    if (!el) return;

    CH.f18 = new Chart(el, {
      data:{ labels, datasets:[] },
      options:{
        ...baseOpts(true),
        plugins:{ ...baseOpts(true).plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } },
        scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Big bags (dia)' } } }
      }
    });

    const ds = [];
    for (const vn of BASE.f18VarNames){
      ds.push(mkLine(vn, BASE.f18SeriesByVar[vn] || [], colorForVar(vn), 'y'));
    }
    ds.push(mkLine('Total (soma)', BASE.f18TotalSeries, THEME.g2, 'y', { borderWidth:3 }));
    ds.push(mkLine('Média (Total)', new Array(labels.length).fill(BASE.f18TotalMean), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));

    CH.f18.data.datasets = ds;
    CH.f18.update();
  })();

  // ===== KPI GERAL SAFRA — render inicial (gauge + textos)
  (function(){
    const elGauge = document.getElementById('chartGaugeSafra');
    const elKpi   = document.getElementById('kp-ating-safra');
    const elDesc  = document.getElementById('kp-ating-desc');
    const elExtra = document.getElementById('kp-ating-extra');

    const fmtPct = (p)=> Number(p).toLocaleString('pt-BR',{ minimumFractionDigits:0, maximumFractionDigits:2 });
    const fmtNum = (n)=> Number(n).toLocaleString('pt-BR');

    if (elKpi && elDesc && elExtra) {
      if (BASE.atingSafraPct == null) {
        elKpi.textContent = '—';
        elDesc.textContent = 'Sem dados válidos no período';
        elExtra.textContent = '—';
      } else {
        elKpi.textContent = `${fmtPct(BASE.atingSafraPct)}%`;
        elDesc.textContent = `${BASE.diasAtingidos}/${BASE.diasComDados} dias ≥ 100%`;
        elExtra.textContent = `Realizado: ${fmtNum(BASE.totalRealSafra)} sacos • Meta: ${fmtNum(BASE.totalMetaSafra)} sacos`;
      }
    }

    if (elGauge) {
      const v = BASE.atingSafraPct == null ? 0 : Math.max(0, Math.min(100, Number(BASE.atingSafraPct)));
      const g = new Chart(elGauge, {
        type: 'doughnut',
        data: {
          labels: ['Atingido','Faltante'],
          datasets: [{
            data: [v, 100 - v],
            backgroundColor: [THEME.g2, hexToRgba(THEME.text, .08)],
            borderWidth: 0
          }]
        },
        options: {
          cutout: '70%',
          plugins: { legend: { display: false }, tooltip: { enabled: false }, noData:{ text:'Sem dados no período' } }
        }
      });
      elGauge._chartInstance = g;
    }
  })();

  /**
 * Calcula preço médio ponderado do dia (CX1..CX5), ignorando Refugo e Resíduo.
 * Retorna float (duas casas) ou null se não der pra calcular.
 * Espera estrutura compatível com seu payload_json (comercial.vendas, producao.romaneio).
 */
  // ===== Mostrar seções iniciais e meta
  function updateGridCols(){
    const isFS = !!document.fullscreenElement;
    if (!isFS){ gridCharts.style.gridTemplateColumns = ''; return; }
    const n = Math.max(1, (()=>{ let c=0; CATALOG.forEach(s=>{ const el=document.getElementById(s.id); if(el && el.style.display!=='none') c++; }); return c; })());
    let cols = Math.ceil(Math.sqrt(n));
    cols = Math.max(2, Math.min(4, cols));
    gridCharts.style.gridTemplateColumns = `repeat(${cols}, minmax(360px, 1fr))`;
  }
  document.addEventListener('fullscreenchange', updateGridCols);
  window.addEventListener('resize', updateGridCols);

  // Estado inicial de seções + metas
  applySecFilter();

  // Metas iniciais em HORAS para os gráficos de tempo
  setTypeMetaHours('log-meta', logMeanMap);
  setTypeMetaHours('prod-carr-meta', prodCarrMeanMap);
  setTypeMetaHours('prod-desc-meta', prodDescMeanMap);
  setMetaHours('prod-parada-meta', <?php echo json_encode($mediaParada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  // Fazenda carregamento é setado no bloco do chart após calcular média diária
</script>
</body>
</html>






