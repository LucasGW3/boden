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
  'qualidade' => ['secQPelada','secQDefeitos','secQUniform'],
  'producao'  => ['secProdSacos','secProdCarreg','secProdDesc','secProdAprov','secProdAting','secProdAtingSafra'],
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
  'secProdSacos'        => ['view',  'dashboard_producao'],
  'secProdCarreg'       => ['view',  'dashboard_producao'],
  'secProdDesc'         => ['view',  'dashboard_producao'],
  'secProdAprov'        => ['view',  'dashboard_producao'],
  'secProdAting'        => ['view',  'dashboard_producao'],
  /* +++ NOVO +++ */
  'secProdAtingSafra'   => ['view',  'dashboard_producao'],
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
    id, ref_date, payload_json,
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
$metricsAvg      = ['l5','p11_dia','p12_dia','f_carr_dia','f_desc_dia'];

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

foreach ($rows as $r) {
  $d = $r['ref_date'];
  if (!isset($byDay[$d])) $byDay[$d] = ['override'=>[], 'sum'=>[], 'avg'=>[]];

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

  $payload = json_decode($r['payload_json'] ?? 'null', true) ?: [];

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
      if (!isset($prodCarrByType[$d][$tipo])) $prodCarrByType[$d][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $prodCarrByType[$d][$tipo]['sum'] += (float)$min;
      $prodCarrByType[$d][$tipo]['cnt'] += 1;
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
      if (!isset($prodDescByType[$d][$tipo])) $prodDescByType[$d][$tipo] = ['sum'=>0.0,'cnt'=>0];
      $prodDescByType[$d][$tipo]['sum'] += (float)$min;
      $prodDescByType[$d][$tipo]['cnt'] += 1;
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
        $comHojeByDate[$d]['sum'] += $num;
        $comHojeByDate[$d]['cnt'] += 1;
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
        $comOntemByDate[$d]['sum'] += $num;
        $comOntemByDate[$d]['cnt'] += 1;
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

/* === Comercial por Variedade via VIEWS (Hoje/Ontem) === */

/* 1) Variedades disponíveis no período/unidade */
$sqlVar = "
  SELECT DISTINCT vp.variedade
  FROM v_precos_comercial_var_ponderado vp
  WHERE vp.ref_date BETWEEN :from AND :to
    AND (
      :u1 = '' OR EXISTS (
        SELECT 1
          FROM v_comercial_vendas cv
         WHERE cv.ref_date  = vp.ref_date
           AND cv.variedade = vp.variedade
           AND cv.unidade   = :u2
      )
    )
  ORDER BY vp.variedade
";
$stVar = pdo()->prepare($sqlVar);
$stVar->execute([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
]);
$comVarNames = $stVar->fetchAll(PDO::FETCH_COLUMN) ?: [];

/* 2) Índices por data (já vieram dos blocos HOJE/ONTEM) */
$idxByDateH = array_flip($labelsCISO_H); // HOJE
$idxByDateO = array_flip($labelsCISO_O); // ONTEM

/* 3) Pesos (SC) por dia e variedade — romaneio */
$sqlW = "
  SELECT
    p.ref_date,
    p.variedade,
    SUM(p.peso_sc) AS sc
  FROM v_romaneio_var_caixa_peso p
  JOIN v_comercial_vendas cv
    ON  cv.ref_date  = p.ref_date
    AND cv.variedade = p.variedade
    AND cv.caixa     = p.caixa
  WHERE p.ref_date >= :from AND p.ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR cv.unidade = :u2)
  GROUP BY p.ref_date, p.variedade
";
$stW = pdo()->prepare($sqlW);
$stW->execute([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
]);

/* 4) Preços HOJE (média por dia/variedade) */
$sqlPH = "
  SELECT vp.ref_date, vp.variedade, vp.preco_ponderado_sc AS preco
  FROM v_precos_comercial_var_ponderado vp
  WHERE vp.ref_date BETWEEN :from AND :to
    AND vp.preco_ponderado_sc IS NOT NULL
    AND (
      :u1 = '' OR EXISTS (
        SELECT 1
          FROM v_comercial_vendas cv
         WHERE cv.ref_date  = vp.ref_date
           AND cv.variedade = vp.variedade
           AND cv.unidade   = :u2
      )
    )
";
$stPH = pdo()->prepare($sqlPH);
$stPH->execute([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
]);

/* 5) Preços ONTEM (ponderado por caixa, inline) */
$sqlPO = "
  SELECT
    p.ref_date,
    p.variedade,
    CASE WHEN SUM(p.peso_sc) > 0
         THEN SUM(p.peso_sc * cv.preco_ontem) / SUM(p.peso_sc)
         ELSE NULL
    END AS preco
  FROM v_romaneio_var_caixa_peso p
  JOIN v_comercial_vendas cv
    ON  cv.ref_date  = p.ref_date
    AND cv.variedade = p.variedade
    AND cv.caixa     = p.caixa
  WHERE p.ref_date >= :from AND p.ref_date < DATE_ADD(:to, INTERVAL 1 DAY)
    AND (:u1 = '' OR cv.unidade = :u2)
    AND cv.preco_ontem IS NOT NULL
  GROUP BY p.ref_date, p.variedade
";
$stPO = pdo()->prepare($sqlPO);
$stPO->execute([
  ':from' => $from->format('Y-m-d'),
  ':to'   => $to->format('Y-m-d'),
  ':u1'   => $unidade,
  ':u2'   => $unidade,
]);

/* 6) Inicializa arrays alinhados às datas HOJE/ONTEM */
$lenH = count($labelsCISO_H);
$lenO = count($labelsCISO_O);
$comHojeVarPrice  = [];
$comHojeVarQty    = [];
$comOntemVarPrice = [];
$comOntemVarQty   = [];

foreach ($comVarNames as $vn) {
  $comHojeVarPrice[$vn]  = array_fill(0, $lenH, null);
  $comHojeVarQty[$vn]    = array_fill(0, $lenH, 0.0);
  $comOntemVarPrice[$vn] = array_fill(0, $lenO, null);
  $comOntemVarQty[$vn]   = array_fill(0, $lenO, 0.0);
}

/* 7) Preenche preços HOJE */
while ($r = $stPH->fetch(PDO::FETCH_ASSOC)) {
  $d  = $r['ref_date'];
  $vn = (string)$r['variedade'];
  $pr = is_numeric($r['preco']) ? (float)$r['preco'] : null;
  if ($pr === null || !isset($idxByDateH[$d]) || !isset($comHojeVarPrice[$vn])) continue;
  $i = $idxByDateH[$d];
  $comHojeVarPrice[$vn][$i] = $pr;
}

/* 8) Preenche preços ONTEM */
while ($r = $stPO->fetch(PDO::FETCH_ASSOC)) {
  $d  = $r['ref_date'];
  $vn = (string)$r['variedade'];
  $pr = is_numeric($r['preco']) ? (float)$r['preco'] : null;
  if ($pr === null || !isset($idxByDateO[$d]) || !isset($comOntemVarPrice[$vn])) continue;
  $i = $idxByDateO[$d];
  $comOntemVarPrice[$vn][$i] = $pr;
}

/* 9) Preenche PESOS (SC) — valem para Hoje e Ontem (mesmo dia) */
while ($r = $stW->fetch(PDO::FETCH_ASSOC)) {
  $d  = $r['ref_date'];
  $vn = (string)$r['variedade'];
  $sc = is_numeric($r['sc']) ? (float)$r['sc'] : 0.0;
  if ($sc <= 0) continue;

  if (isset($idxByDateH[$d]) && isset($comHojeVarQty[$vn])) {
    $comHojeVarQty[$vn][$idxByDateH[$d]] += $sc;
  }
  if (isset($idxByDateO[$d]) && isset($comOntemVarQty[$vn])) {
    $comOntemVarQty[$vn][$idxByDateO[$d]] += $sc;
  }
}

/* 10) Ordena nomes de variedade como antes */
natcasesort($comVarNames);
$comVarNames = array_values($comVarNames);

/* =============================================================================
 * 8) F18 — Big bag por Variedade (LINHAS por dia)
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
 * 9) Métricas resumo (gerais)
 * ========================================================================== */
$mediaLogLegacy   = $avgOf($series['l5']);
$mediaPelada= $avgOf($series['q6_dia']);
$mediaDefeitos=$avgOf($series['q7_dia']);
$mediaUniform =$avgOf($series['q8_dia']);
$mediaCarrLegacy  = $avgOf($series['f_carr_dia']);
$mediaDesc  = $avgOf($series['f_desc_dia']);
$mediaAprov = $avgOf($series['p_aprov_dia']);

ksort($fazCarrRawSumPerDay);
ksort($fazCarrRawCntPerDay);
$labelsISO  = array_keys($byDay);
$labelsRawF = array_keys($fazCarrRawSumPerDay);

$rawGlobalSum = array_sum($fazCarrRawSumPerDay);
$rawGlobalCnt = array_sum($fazCarrRawCntPerDay);
$mediaFazCarrRaw = ($rawGlobalCnt>0) ? round($rawGlobalSum/$rawGlobalCnt, 3) : null;

/* =============================================================================
 * 10) Séries por tipo (produção, fazenda e logística)
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

foreach (array_keys($byDay) as $d) {
  $carrValsForMean = [];
  foreach ($typesProd as $t) {
    $val = (isset($prodCarrByType[$d][$t]) && $prodCarrByType[$d][$t]['cnt']>0)
      ? round($prodCarrByType[$d][$t]['sum'] / $prodCarrByType[$d][$t]['cnt'], 3)
      : null;
    $seriesProdCarrTipos[$t][] = $val;
    if ($val !== null) $carrValsForMean[] = $val;
  }
  $prodCarrDailyMeanSeries[] = count($carrValsForMean) ? round(array_sum($carrValsForMean)/count($carrValsForMean), 3) : null;

  $descValsForMean = [];
  foreach ($typesProdDesc as $t) {
    $val = (isset($prodDescByType[$d][$t]) && $prodDescByType[$d][$t]['cnt']>0)
      ? round($prodDescByType[$d][$t]['sum'] / $prodDescByType[$d][$t]['cnt'], 3)
      : null;
    $seriesProdDescTipos[$t][] = $val;
    if ($val !== null) $descValsForMean[] = $val;
  }
  $prodDescDailyMeanSeries[] = count($descValsForMean) ? round(array_sum($descValsForMean)/count($descValsForMean), 3) : null;

  foreach ($typesFaz as $t) {
    $seriesFazCarrTipos[$t][] = (isset($fazCarrByType[$d][$t]) && $fazCarrByType[$d][$t]['cnt']>0)
      ? round($fazCarrByType[$d][$t]['sum'], 3) : null;
  }

  $logValsForMean = [];
  foreach ($typesLog as $t) {
    $val = (isset($logByType[$d][$t]) && $logByType[$d][$t]['cnt']>0)
      ? round($logByType[$d][$t]['sum'] / $logByType[$d][$t]['cnt'], 3)
      : null;
    $seriesLogTipos[$t][] = $val;
    if ($val !== null) $logValsForMean[] = $val;
  }
  $logDailyMeanSeries[] = count($logValsForMean) ? round(array_sum($logValsForMean)/count($logValsForMean), 3) : null;
}

/* Médias do período (min) */
$avgOf = $avgOf;
$mediaTMC_period = $avgOf($prodCarrDailyMeanSeries);
$mediaTMD_period = $avgOf($prodDescDailyMeanSeries);
$mediaLog_all    = $avgOf($logDailyMeanSeries);

/* LOGÍSTICA (2 veículos + média) */
$desiredLogTypes = ['Carreta LS', 'Truck'];
$typesLogSel = array_values(array_intersect($desiredLogTypes, $typesLog));
if (!$typesLogSel) {
  $typesLogSel = array_slice($typesLog, 0, min(2, count($typesLog)));
}

$seriesLogTiposSel = [];
foreach ($typesLogSel as $t) { $seriesLogTiposSel[$t] = $seriesLogTipos[$t] ?? []; }

$logDailyMeanSel = [];
$lenLabels = count($labels);
for ($i=0; $i<$lenLabels; $i++) {
  $vals = [];
  foreach ($typesLogSel as $t) {
    $v = $seriesLogTiposSel[$t][$i] ?? null;
    if ($v !== null) $vals[] = (float)$v;
  }
  $logDailyMeanSel[] = (count($vals) === 2) ? round(($vals[0]+$vals[1])/2, 3) : (count($vals) ? round(array_sum($vals)/count($vals), 3) : null);
}
$mediaLogSel = $avgOf($logDailyMeanSel);

$fazCarrRawSumArr = [];
$fazCarrRawCntArr = [];
foreach ($labelsISO as $d) {
  $fazCarrRawSumArr[] = isset($fazCarrRawSumPerDay[$d]) ? round((float)$fazCarrRawSumPerDay[$d], 3) : null;
  $fazCarrRawCntArr[] = isset($fazCarrRawCntPerDay[$d]) ? (int)$fazCarrRawCntPerDay[$d] : null;
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
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <script>
    tailwind.config = {
      theme: { extend: {
        fontFamily: { sans: ['Nunito','ui-sans-serif','system-ui'] },
        colors: { brand: { bg:'#F4F9F2', surface:'#FFFFFF', line:'#E5F2DE', primary:'#5FB141', primaryDark:'#3C8F28', text:'#273418', muted:'#7A8F6B' } },
        borderRadius: { pill:'9999px', xl2:'1rem' },
        boxShadow: { soft:'0 6px 18px rgba(60,143,40,0.08)' }
      } }
    }
  </script>
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

    .modal-overlay{ position:fixed; inset:0; background:rgba(17,24,39,.45); -webkit-backdrop-filter:blur(10px); backdrop-filter:blur(10px); z-index:50; }
    .modal-card{ width:98vw; max-width:1680px; max-height:96vh; }
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
      overflow-x: auto;
      padding-right: .25rem;
      padding-bottom: .25rem;
      scroll-behavior: smooth;
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
        <h2 class="font-semibold mb-1">Safra • Atingimento Geral</h2>
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
        <h2 class="font-semibold mb-1">Comercial • Preço por SC • Hoje (R$)</h2>
        <p id="com-meta" class="text-xs text-brand-muted mb-2">—</p>
        <!-- (NOVO) Filtro dentro do card -->
        <div id="comercialVarPicker" class="mb-3 flex flex-wrap gap-2 text-xs"></div>
        <canvas id="chartComercialMedia"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secComercialOntem', $allowedSections, true)): ?>
      <section id="secComercialOntem" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Comercial • Preço por SC • Realizado (R$)</h2>
        <p id="com-ontem-meta" class="text-xs text-brand-muted mb-2">—</p>
        <!-- (NOVO) Filtro dentro do card -->
        <div id="comercialOntemVarPicker" class="mb-3 flex flex-wrap gap-2 text-xs"></div>
        <canvas id="chartComercialOntem"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secLogistica', $allowedSections, true)): ?>
      <section id="secLogistica" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Logística • Tempo de transporte (h)</h2>
        <p id="log-meta" class="text-xs text-brand-muted mb-3">—</p>
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

      <?php if (in_array('secProdSacos', $allowedSections, true)): ?>
      <section id="secProdSacos" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-3">Produção • Sacos (total) e por colaborador</h2>
        <canvas id="chartProdSacos"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdAting', $allowedSections, true)): ?>
      <section id="secProdAting" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Produção • Atingimento da Meta (%) × Sacos/Dia</h2>
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
  <div id="graphsModal" class="hidden">
    <div class="modal-overlay"></div>
    <div class="fixed inset-0 flex items-center justify-center z-50 p-3 sm:p-6">
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

  // === Helpers globais (HOISTED) ===
// Defina só uma vez no arquivo, no topo do <script>
window.EXCLUDE_VARS = new Set(['Refugo','Resíduo','Residuo','Refugo/Resíduo']);

function filterVarList(names){
  names = names || [];
  const out = [];
  for (let i = 0; i < names.length; i++){
    const v = (names[i] || '').trim();
    if (!window.EXCLUDE_VARS.has(v)) out.push(v);
  }
  return out;
}

function dailyRevenue(priceMap, qtyMap, varSel, len){
  const out = new Array(len).fill(null);
  for (let i = 0; i < len; i++){
    let sum = 0, any = false;
    for (let k = 0; k < varSel.length; k++){
      const v = varSel[k];
      const pArr = (priceMap[v] || []);
      const qArr = (qtyMap[v]   || []);
      const p = pArr[i];
      const q = qArr[i];
      if (p != null && q != null && !Number.isNaN(p) && !Number.isNaN(q) && Number(q) > 0){
        sum += Number(p) * Number(q);
        any = true;
      }
    }
    out[i] = any ? sum : null;
  }
  return out;
}

  const THEME = { g1:'#9DBF21', g2:'#56A632', g3:'#63AA35', soft:'#cfe87a', red:'#EA0004', yellow:'#FFC107', text:'#1e1e1e' };

  document.getElementById('btnFull')?.addEventListener('click',()=>{
    if(!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
    else document.exitFullscreen();
  });

  // ===== Dados do PHP =====
  const labels  = <?php echo json_encode($labels, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
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

  // ===== NOVO: Comercial ponderado por variedade =====
  const comVarNames      = <?php echo json_encode($comVarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeVarPrice  = <?php echo json_encode($comHojeVarPrice, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comHojeVarQty    = <?php echo json_encode($comHojeVarQty, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemVarPrice = <?php echo json_encode($comOntemVarPrice, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const comOntemVarQty   = <?php echo json_encode($comOntemVarQty, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== NOVO F18 (linhas)
  const f18VarNames     = <?php echo json_encode($f18VarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18SeriesByVar  = <?php echo json_encode($f18SeriesByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalSeries  = <?php echo json_encode($f18TotalSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalMean    = <?php echo json_encode($f18TotalMean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: médias gerais (minutos)
  const mediaDesc  = <?php echo json_encode($mediaDesc, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // minutos
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
  const logTiposSel   = <?php echo json_encode($seriesLogTiposSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const logDailyMeanSel = <?php echo json_encode($logDailyMeanSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaLogSel     = <?php echo json_encode($mediaLogSel, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

  // Produção / Fazenda — minutos
  const prodCarrTipos = <?php echo json_encode($seriesProdCarrTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescTipos = <?php echo json_encode($seriesProdDescTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrTipos  = <?php echo json_encode($seriesFazCarrTipos,  JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: médias diárias (entre tipos) — minutos
  const prodCarrDailyMean = <?php echo json_encode($prodCarrDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescDailyMean = <?php echo json_encode($prodDescDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  const mediaTMC_period   = <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min
  const mediaTMD_period   = <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

  // Datas ISO gerais
  const labelsISO  = <?php echo json_encode($labelsISO, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== BRUTOS da Fazenda Carregamento — minutos
  const fazCarrRawSum = <?php echo json_encode($fazCarrRawSumArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrRawCnt = <?php echo json_encode($fazCarrRawCntArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaFazCarrRaw = <?php echo json_encode($mediaFazCarrRaw, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>; // min

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

    // NOVO: Comercial ponderado por variedade
    comVarNames: [...(comVarNames || [])],
    comHojeVarPrice: JSON.parse(JSON.stringify(comHojeVarPrice || {})),
    comHojeVarQty:   JSON.parse(JSON.stringify(comHojeVarQty   || {})),
    comOntemVarPrice: JSON.parse(JSON.stringify(comOntemVarPrice || {})),
    comOntemVarQty:   JSON.parse(JSON.stringify(comOntemVarQty   || {})),

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
    mediaLogSel: mediaLogSel,

    // médias diárias (entre tipos) em minutos
    prodCarrDailyMean: [...prodCarrDailyMean],
    prodDescDailyMean: [...prodDescDailyMean],

    // BRUTOS FAZENDA
    fazCarrRawSum: [...fazCarrRawSum],
    fazCarrRawCnt: [...fazCarrRawCnt],

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

    // F18
    f18VarNames: [...f18VarNames],
    f18SeriesByVar: JSON.parse(JSON.stringify(f18SeriesByVar)),
    f18TotalSeries: [...f18TotalSeries],
    f18TotalMean: f18TotalMean
  };
  const CH = {}; // refs dos gráficos

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
    {id:'secProdSacos',      label:'Sacos & por colaborador',        icon:ico.producao,  role:'producao'},
    {id:'secProdAting',      label:'Atingimento da meta x Sacos/Dia',icon:ico.producao,  role:'producao' },
    {id:'secProdCarreg',     label:'Carregamento por tipo',          icon:ico.producao,  role:'producao'},
    {id:'secProdDesc',       label:'Descarregamento por tipo',       icon:ico.producao,  role:'producao'},
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
  const CHART_SECS_WITH_TIME = new Set(['secLogistica','secProdCarreg','secProdDesc','secFazCarreg']); // gráficos que exibem horas

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

// ======== (NOVO) Helpers ponderados Comercial =========
function weightedDailySeries(priceMap, qtyMap, varSel, len){
  const out = new Array(len).fill(null);
  for (let i=0;i<len;i++){
    let ws=0, wq=0;
    for (const v of varSel){
      const pArr = priceMap[v] || [];
      const qArr = qtyMap[v] || [];
      const p = pArr[i]; const q = qArr[i];
      if (p != null && !Number.isNaN(p) && Number(p) > 0 && q != null && !Number.isNaN(q) && Number(q) > 0){
        ws += Number(p) * Number(q);
        wq += Number(q);
      }
    }
    out[i] = (wq > 0) ? (ws / wq) : null;
  }
  return out;
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
function flatQtyForSelection(qtyMap, varSel, len){
  const out = new Array(len).fill(0);
  for (const v of varSel){
    const arr = qtyMap[v] || [];
    for (let i=0;i<len;i++){
      const q = arr[i];
      if (q != null && !Number.isNaN(q) && Number(q) > 0) out[i] += Number(q);
    }
  }
  return out;
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

// === Helpers globais usados em vários blocos ===
function isAllNull(arr){
  return !arr || arr.every(v => v == null);
}
function sumNumbers(arr){
  return (arr || []).reduce((s, v) => s + ((v != null && !Number.isNaN(Number(v))) ? Number(v) : 0), 0);
}

  function applyDateFilterClient(dFrom, dTo){
    const url = new URL(location.href);
    dFrom ? url.searchParams.set('from', dFrom) : url.searchParams.delete('from');
    dTo   ? url.searchParams.set('to',   dTo)   : url.searchParams.delete('to');
    history.replaceState(null,'', url.toString());

    const keep   = idxRangeByDateISO(BASE.labelsISO,    dFrom, dTo);
    const keepH  = idxRangeByDateISO(BASE.labelsCISO_H, dFrom, dTo);
    const keepO  = idxRangeByDateISO(BASE.labelsCISO_O, dFrom, dTo);
    window._keepIdx  = keep;
    window._keepIdxH = keepH;
    window._keepIdxO = keepO;

    const L   = sliceByIdx(BASE.labels,  keep);
    const LCH = sliceByIdx(BASE.labelsC_H, keepH);
    const LCO = sliceByIdx(BASE.labelsC_O, keepO);

    const Sfil = {};
    for (const k of Object.keys(BASE.S)) Sfil[k] = sliceByIdx(BASE.S[k], keep);

    // Recalcular médias gerais do recorte (MINUTOS)
    const mediaPelF   = avgNonNull(Sfil.q6_dia);
    const mediaDefF   = avgNonNull(Sfil.q7_dia);
    const mediaUniF   = avgNonNull(Sfil.q8_dia);
    const mediaDescF  = avgNonNull(Sfil.f_desc_dia);
    const mediaAprovF = avgNonNull(Sfil.p_aprov_dia);

    // PRODUÇÃO: médias diárias (entre tipos) re-filtradas — MINUTOS
    const prodCarrMeanF_min = sliceByIdx(BASE.prodCarrDailyMean, keep);
    const prodDescMeanF_min = sliceByIdx(BASE.prodDescDailyMean, keep);
    const mediaTMCF_min     = avgNonNull(prodCarrMeanF_min);
    const mediaTMDF_min     = avgNonNull(prodDescMeanF_min);

    // LOGÍSTICA (2 veículos): média diária — MINUTOS
    const logMeanTwo_min = sliceByIdx(BASE.logDailyMeanSel, keep);
    const mediaLogF      = avgNonNull(logMeanTwo_min);

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

    // === Comercial HOJE (ponderado + receita R$ no recorte) ===
    if (CH.comercial){
      const sel = (window._comercialSelH && window._comercialSelH.length) ? window._comercialSelH : filterVarList(BASE.comVarNames);

      // Séries completas
      const priceFull = weightedDailySeries(BASE.comHojeVarPrice, BASE.comHojeVarQty, sel, BASE.labelsCISO_H.length); // R$/SC
      const qtyFull   = flatQtyForSelection(BASE.comHojeVarQty,   sel, BASE.labelsCISO_H.length);                      // SC
      const revFull   = dailyRevenue(BASE.comHojeVarPrice, BASE.comHojeVarQty, sel, BASE.labelsCISO_H.length);         // R$

      // Recorte
      const LCH   = sliceByIdx(BASE.labelsC_H,  keepH);
      const price = sliceByIdx(priceFull, keepH);
      const qty   = sliceByIdx(qtyFull,   keepH);
      const rev   = sliceByIdx(revFull,   keepH);

      const hasW  = sumNumbers(qty) > 0;
      const medW  = hasW ? weightedMean(price, qty) : null;

      CH.comercial.data.labels            = LCH;
      CH.comercial.data.datasets[0].data  = rev; // barras = R$ total
      CH.comercial.data.datasets[1].data  = (medW!=null) ? new Array(LCH.length).fill(medW) : new Array(LCH.length).fill(null); // linha = média ponderada R$/SC
      CH.comercial.update();
      setMetaMoney(document.getElementById('com-meta'), medW);
    }

    // === Comercial ONTEM (ponderado + receita R$ no recorte) ===
    if (CH.comercialOntem){
      const sel = (window._comercialSelO && window._comercialSelO.length) ? window._comercialSelO : filterVarList(BASE.comVarNames);

      const priceFull = weightedDailySeries(BASE.comOntemVarPrice, BASE.comOntemVarQty, sel, BASE.labelsCISO_O.length);
      const qtyFull   = flatQtyForSelection(BASE.comOntemVarQty,   sel, BASE.labelsCISO_O.length);
      const revFull   = dailyRevenue(BASE.comOntemVarPrice, BASE.comOntemVarQty, sel, BASE.labelsCISO_O.length);

      const LCO   = sliceByIdx(BASE.labelsC_O,  keepO);
      const price = sliceByIdx(priceFull, keepO);
      const qty   = sliceByIdx(qtyFull,   keepO);
      const rev   = sliceByIdx(revFull,   keepO);

      const hasW  = sumNumbers(qty) > 0;
      const medW  = hasW ? weightedMean(price, qty) : null;

      CH.comercialOntem.data.labels            = LCO;
      CH.comercialOntem.data.datasets[0].data  = rev; // barras = R$ total
      CH.comercialOntem.data.datasets[1].data  = (medW!=null) ? new Array(LCO.length).fill(medW) : new Array(LCO.length).fill(null);
      CH.comercialOntem.update();
      setMetaMoney(document.getElementById('com-ontem-meta'), medW);
    }

    // ===== Logística (2 veículos + média) — HORAS
    if (CH.logistica){
      CH.logistica.data.labels = L;

      for (let i=0;i<BASE.typesLogSel.length;i++){
        const key = BASE.typesLogSel[i];
        const serie = seriesMinToHours(sliceByIdx(BASE.logTiposSel[key] || [], keep));
        CH.logistica.data.datasets[i].data = serie;
      }
      const idxMean = CH.logistica.data.datasets.length-1;
      CH.logistica.data.datasets[idxMean].data = seriesMinToHours(logMeanTwo_min);

      CH.logistica.update();
      setMetaHours('log-meta', mediaLogF);
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
    if (CH.prodSacos){
      CH.prodSacos.data.labels = L;
      CH.prodSacos.data.datasets[0].data = Sfil.p16_dia;
      CH.prodSacos.data.datasets[1].data = Sfil.p15_dia;
      CH.prodSacos.update();
    }

    // Produção Carregamento — HORAS
    if (CH.prodCarreg){
      CH.prodCarreg.data.labels = L;
      for (let i=0;i<BASE.typesProd.length;i++){
        const key = BASE.typesProd[i];
        const serie = seriesMinToHours(sliceByIdx(BASE.prodCarrTipos[key], keep));
        CH.prodCarreg.data.datasets[i].data = serie;
      }
      const idxMean = CH.prodCarreg.data.datasets.length-1;
      CH.prodCarreg.data.datasets[idxMean].data = seriesMinToHours(prodCarrMeanF_min);
      CH.prodCarreg.update();
      setMetaHours('prod-carr-meta', mediaTMCF_min);
    }

    // Produção Descarregamento — HORAS
    if (CH.prodDesc){
      CH.prodDesc.data.labels = L;
      for (let i=0;i<BASE.typesProdDesc.length;i++){
        const key = BASE.typesProdDesc[i];
        const serie = seriesMinToHours(sliceByIdx(BASE.prodDescTipos[key], keep));
        CH.prodDesc.data.datasets[i].data = serie;
      }
      const idxMean = CH.prodDesc.data.datasets.length-1;
      CH.prodDesc.data.datasets[idxMean].data = seriesMinToHours(prodDescMeanF_min);
      CH.prodDesc.update();
      setMetaHours('prod-desc-meta', mediaTMDF_min);
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

      const ds = [];
      const perTypeSeriesH = [];
      for (const typeName of BASE.typesFaz){
        const serieH = seriesMinToHours(sliceByIdx(BASE.fazCarrTipos[typeName] || [], keep));
        perTypeSeriesH.push(serieH);
        ds.push(mkLine(`${typeName} (total/dia)`, serieH, colorForType(typeName, true), 'y', { borderWidth:3 }));
      }

      const dailyMeanH = L.map((_, i) => {
        const vals = perTypeSeriesH
        .map(s => s[i])
        .filter(v => v != null && !Number.isNaN(v) && Number(v) > 0);
        return vals.length ? (vals.reduce((a,b)=>a+Number(b),0) / vals.length) : null;
      });

      ds.push(mkLine('Média diária (Fazenda • Carregamento)', dailyMeanH, THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));

      CH.fazCarr.data.datasets = ds;
      CH.fazCarr.update();

      const mediaPeriodoMin = (function(arrH){
        let s=0,c=0; for(const v of arrH){ if(v!=null && !Number.isNaN(v)){ s+=Number(v); c++; } }
        const mediaH = c? (s/c) : null;
        return mediaH==null? null : mediaH*60;
      })(dailyMeanH);

      setMetaHours('faz-carreg-meta', mediaPeriodoMin);
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
    const idx = (BASE.f18VarNames || []).indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };

// ===== Comercial HOJE (barras = R$ total; linha = média ponderada R$/SC) =====
(function(){
  const el = document.getElementById('chartComercialMedia');
  if (!el) return;

  CH.comercial = new Chart(el, {
    data: { labels: BASE.labelsC_H, datasets: [
      // Barras: valor total do dia (R$)
      mkBar('Valor total do dia (R$)', new Array(BASE.labelsC_H.length).fill(null), THEME.g2, 'y1'),
      // Linha tracejada: média ponderada R$/SC (constante no recorte)
      mkLine('Média ponderada (R$/SC)', new Array(BASE.labelsC_H.length).fill(null), THEME.g3, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
    ]},
    options: {
      ...baseOpts(true),
      plugins:{
        ...baseOpts(true).plugins,
        tooltip:{ callbacks:{ label:(ctx)=>{
          const v = ctx.parsed.y;
          if (ctx.dataset.yAxisID === 'y1') {
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 }));
            return `${ctx.dataset.label}: R$ ${txt}`;
          } else {
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
            return `${ctx.dataset.label}: R$ ${txt}/SC`;
          }
        }}}
      },
      scales: {
        y:  { beginAtZero:true, position:'left',  title:{ display:true, text:'R$/SC' } },
        y1: { beginAtZero:true, position:'right', title:{ display:true, text:'R$ (total do dia)' }, grid:{ drawOnChartArea:false } }
      }
    }
  });

  // Seletor e cálculo inicial (já ignorando Refugo/Resíduo)
  const varNames = filterVarList(BASE.comVarNames);
  buildVarPicker('comercialVarPicker', varNames, varNames, (sel) => {
    window._comercialSelH = sel;

    const idx = (window._keepIdxH && window._keepIdxH.length)
      ? window._keepIdxH
      : BASE.labelsCISO_H.map((_, i) => i);

    // séries completas
    const priceFull = weightedDailySeries(BASE.comHojeVarPrice, BASE.comHojeVarQty, sel, BASE.labelsCISO_H.length);
    const qtyFull   = flatQtyForSelection   (BASE.comHojeVarQty,                     sel, BASE.labelsCISO_H.length);
    const revFull   = dailyRevenue          (BASE.comHojeVarPrice, BASE.comHojeVarQty, sel, BASE.labelsCISO_H.length);

    // aplica recorte
    const price = sliceByIdx(priceFull, idx);
    const qty   = sliceByIdx(qtyFull,   idx);
    const rev   = sliceByIdx(revFull,   idx);

    // atualiza o gráfico (barras = R$ total do dia)
    CH.comercial.data.datasets[0].data = rev;

    // média ponderada R$/SC no recorte
    const hasW = sumNumbers(qty) > 0;
    const medW = hasW ? weightedMean(price, qty) : null;

    // linha horizontal constante com a média do recorte (mesmo número de pontos que o gráfico já tem)
    CH.comercial.data.datasets[1].data = (medW != null)
      ? new Array(CH.comercial.data.labels.length).fill(medW)
      : new Array(CH.comercial.data.labels.length).fill(null);

    CH.comercial.update();
    setMetaMoney(document.getElementById('com-meta'), medW); // mostra a média do recorte (sem fallback)
  });
})();

  // ===== Comercial ONTEM (inicia ponderado) =====
 // ===== Comercial ONTEM (barras = R$ total; linha = média ponderada R$/SC) =====
(function(){
  const el = document.getElementById('chartComercialOntem');
  if (!el) return;

  CH.comercialOntem = new Chart(el, {
    data: { labels: BASE.labelsC_O, datasets: [
      mkBar('Valor total do dia (R$)', new Array(BASE.labelsC_O.length).fill(null), THEME.g1, 'y1'),
      mkLine('Média ponderada (R$/SC)', new Array(BASE.labelsC_O.length).fill(null), THEME.g3, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
    ]},
    options: {
      ...baseOpts(true),
      plugins:{
        ...baseOpts(true).plugins,
        tooltip:{ callbacks:{ label:(ctx)=>{
          const v = ctx.parsed.y;
          if (ctx.dataset.yAxisID === 'y1') {
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 }));
            return `${ctx.dataset.label}: R$ ${txt}`;
          } else {
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
            return `${ctx.dataset.label}: R$ ${txt}/SC`;
          }
        }}}
      },
      scales: {
        y:  { beginAtZero:true, position:'left',  title:{ display:true, text:'R$/SC' } },
        y1: { beginAtZero:true, position:'right', title:{ display:true, text:'R$ (total do dia)' }, grid:{ drawOnChartArea:false } }
      }
    }
  });

  const varNames = filterVarList(BASE.comVarNames);
  buildVarPicker('comercialOntemVarPicker', varNames, varNames, (sel) => {
  window._comercialSelO = sel;

  const idx = (window._keepIdxO && window._keepIdxO.length)
    ? window._keepIdxO
    : BASE.labelsCISO_O.map((_, i) => i);

  const priceFull = weightedDailySeries(BASE.comOntemVarPrice, BASE.comOntemVarQty, sel, BASE.labelsCISO_O.length);
  const qtyFull   = flatQtyForSelection   (BASE.comOntemVarQty,                     sel, BASE.labelsCISO_O.length);
  const revFull   = dailyRevenue          (BASE.comOntemVarPrice, BASE.comOntemVarQty, sel, BASE.labelsCISO_O.length);

  const price = sliceByIdx(priceFull, idx);
  const qty   = sliceByIdx(qtyFull,   idx);
  const rev   = sliceByIdx(revFull,   idx);

  CH.comercialOntem.data.datasets[0].data = rev;

  const hasW = sumNumbers(qty) > 0;
  const medW = hasW ? weightedMean(price, qty) : null;

  CH.comercialOntem.data.datasets[1].data = (medW != null)
    ? new Array(CH.comercialOntem.data.labels.length).fill(medW)
    : new Array(CH.comercialOntem.data.labels.length).fill(null);

  CH.comercialOntem.update();
  setMetaMoney(document.getElementById('com-ontem-meta'), medW);
});
})();

  // ===== LOGÍSTICA (2 veículos + média) — HORAS
  (function(){
    const el = document.getElementById('chartLogistica');
    if (!el) return;
    CH.logistica = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });

    const ds = (BASE.typesLogSel || []).map(k => ({ ...mkLine(k, seriesMinToHours(BASE.logTiposSel[k]||[]), colorForLog(k), 'y') }));
    ds.push(mkLine('Média (Carreta LS + Truck)', seriesMinToHours(BASE.logDailyMeanSel), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ));
    CH.logistica.data.datasets = ds; CH.logistica.update();

    setMetaHours('log-meta', BASE.mediaLogSel);
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

  // ===== Produção: Atingimento da Meta (%) — versão simples (só 1 linha)
  (function(){
    const el = document.getElementById('chartProdAting');
    if (!el) return;

    const hasAting = (BASE.atingPct || []).some(v => v != null && !Number.isNaN(v));

    if (!hasAting) {
      CH.prodAting = new Chart(el, {
        data: { labels, datasets: [] },
        options: {
          responsive: true,
          plugins: { legend: { display:false }, noData: { text:'Sem dados no período' } },
          scales: { y:{ beginAtZero:true, suggestedMax:120, title:{ display:true, text:'Atingimento (%)' } } }
        }
      });
      const elMeta = document.getElementById('prod-ating-meta');
      if (elMeta) elMeta.textContent = '—';
      return;
    }

    CH.prodAting = new Chart(el, {
      data: {
        labels,
        datasets: [
          mkLine('Meta', BASE.atingPct, THEME.g2, 'y', { borderWidth:3 })
        ]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position:'bottom' },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const v = ctx.parsed.y;
                const txt = (v==null?'-':Number(v).toLocaleString('pt-BR',{ minimumFractionDigits:0, maximumFractionDigits:2 }));
                return `${ctx.dataset.label}: ${txt} %`;
              }
            }
          },
          noData:{ text:'Sem dados no período' }
        },
        scales: {
          y: { beginAtZero:true, suggestedMax:120, title:{ display:true, text:'Atingimento (%)' } }
        }
      }
    });

    const elMeta = document.getElementById('prod-ating-meta');
    if (elMeta) elMeta.textContent = '—';
  })();

  // ===== Produção: Carregamento — HORAS
  (function(){
    const el = document.getElementById('chartProdCarreg');
    if (!el) return;
    CH.prodCarreg = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });
    const ds = typesProd.map(k => ({ ...mkLine(k, seriesMinToHours(prodCarrTipos[k]||[]), (colorForType(k, false, false)), 'y') }));
    ds.push(mkLine('Média diária (entre tipos)', seriesMinToHours(BASE.prodCarrDailyMean), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ));
    CH.prodCarreg.data.datasets = ds; CH.prodCarreg.update();
    setMetaHours('prod-carr-meta', <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  // ===== Produção: Descarregamento — HORAS
  (function(){
    const el = document.getElementById('chartProdDesc');
    if (!el) return;
    CH.prodDesc = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });
    const ds = typesProdDesc.map(k => ({ ...mkLine(k, seriesMinToHours(prodDescTipos[k]||[]), (colorForType(k, false, true)), 'y') }));
    ds.push(mkLine('Média diária (entre tipos)', seriesMinToHours(BASE.prodDescDailyMean), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 } ));
    CH.prodDesc.data.datasets = ds; CH.prodDesc.update();
    setMetaHours('prod-desc-meta', <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
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

    const ds = [];
    const perTypeSeriesH = [];
    for (const typeName of BASE.typesFaz){
      const serieH = seriesMinToHours(BASE.fazCarrTipos[typeName] || new Array(labels.length).fill(null));
      perTypeSeriesH.push(serieH);
      ds.push(mkLine(`${typeName} (total/dia)`, serieH, colorForType(typeName, true), 'y', { borderWidth:3 }));
    }

    const dailyMeanH = labels.map((_, i) => {
      const vals = perTypeSeriesH
        .map(s => s[i])
        .filter(v => v != null && !Number.isNaN(v) && Number(v) > 0);
      return vals.length ? (vals.reduce((a,b)=>a+Number(b),0) / vals.length) : null;
    });

    const mediaPeriodoMin = (function(arrH){
      let s=0,c=0; for(const v of arrH){ if(v!=null && !Number.isNaN(v)){ s+=Number(v); c++; } }
      const mediaH = c? (s/c) : null;
      return mediaH==null? null : mediaH*60;
    })(dailyMeanH);

    ds.push(mkLine('Média diária (Fazenda • Carregamento)', dailyMeanH, THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));

    CH.fazCarr = new Chart(el, {
      data:{ labels, datasets: ds },
      options:{ ...hoursOpts, plugins:{ ...hoursOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } }
    });

    setMetaHours('faz-carreg-meta', mediaPeriodoMin);
  })();

  // ===== Pessoas (F17)
  (function(){
    const el = document.getElementById('chartFazendaPessoas');
    if (!el) return;
    CH.fazPessoas = new Chart(el, {
      data:{ labels, datasets:[
        mkBar ('F17 Pessoas/dia (bruto)', S.f17_dia, THEME.g3, 'y'),
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
        mkBar ('F19 Colhedora/dia (bruto)', S.f19_dia, THEME.g2, 'y'),
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
  setMetaHours('log-meta', BASE.mediaLogSel);
  setMetaHours('prod-carr-meta', <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  setMetaHours('prod-desc-meta', <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  // Fazenda carregamento é setado no bloco do chart após calcular média diária
</script>
</body>
</html>
