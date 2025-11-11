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
   (ATUALIZAÇÃO: adicionamos o secComercialOntem) */
$SECTIONS_BY_ROLE = [
  'comercial' => ['secComercial','secComercialOntem'],
  'logistica' => ['secLogistica'],
  'qualidade' => ['secQPelada','secQDefeitos','secQUniform'],
  'producao'  => ['secProdSacos','secProdCarreg','secProdDesc','secProdAprov'],
  'fazenda'   => ['secFazCarreg','secFazDesc','secFazPessoas','secFazColhedora','secPie'],
];
$ALL_SECTIONS = array_values(array_unique(array_merge(...array_values($SECTIONS_BY_ROLE))));

$CAP_BY_SECTION = [
  'secComercial'        => ['view',  'dashboard_comercial'],
  'secComercialOntem'   => ['view',  'dashboard_comercial'], // mesmo capability
  'secLogistica'        => ['view',  'dashboard_logistica'],
  'secQPelada'          => ['view',  'dashboard_qualidade'],
  'secQDefeitos'        => ['view',  'dashboard_qualidade'],
  'secQUniform'         => ['view',  'dashboard_qualidade'],
  'secProdSacos'        => ['view',  'dashboard_producao'],
  'secProdCarreg'       => ['view',  'dashboard_producao'],
  'secProdDesc'         => ['view',  'dashboard_producao'],
  'secProdAprov'        => ['view',  'dashboard_producao'],
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

/* Unidades permitidas (null = sem restrição) */
$unitsAllowed     = get_allowed_units_for_user($uid);
$restrictUnitsSQL = '';
$paramsUnits      = [];

if (is_array($unitsAllowed)) {
  if ($unitsAllowed) {
    $ph = [];
    foreach ($unitsAllowed as $i=>$uVal) { $ph[]=":ru$i"; $paramsUnits[":ru$i"]=$uVal; }
    $restrictUnitsSQL = " AND unidade IN (".implode(',', $ph).") ";
    if ($unidade !== '' && !in_array($unidade, $unitsAllowed, true)) $unidade = '';
  } else {
    $restrictUnitsSQL = " AND 1=0 ";
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
  WHERE ref_date BETWEEN :from AND :to
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
    $v = (float)$maybe;
    return ($v>=60) ? $v : $v*60;
  }
  return hhmm_to_min($maybe);
}

$prodCarrByType = [];   // produção carregamento por tipo
$prodDescByType = [];   // produção descarregamento por tipo
$fazCarrByType  = [];   // fazenda carregamento por tipo

// NOVO: BRUTOS FAZENDA CARREGAMENTO (para média correta por período e por filtro)
$fazCarrRawSumPerDay = []; // soma dos minutos brutos por dia (todas as entradas, todos os tipos)
$fazCarrRawCntPerDay = []; // contagem de entradas brutas por dia

$allTypesProd      = [];
$allTypesProdDesc  = [];
$allTypesFaz       = [];

/* Somente para outras métricas (não usadas na média entre tipos de produção) */
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

  // ===== Fazenda: CARREGAMENTO por tipo (valores brutos por tipo) + NOVO: bruto global para média
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

      // BRUTO global (todas as entradas/tipos) para média correta
      if (!isset($fazCarrRawSumPerDay[$d])) { $fazCarrRawSumPerDay[$d]=0.0; $fazCarrRawCntPerDay[$d]=0; }
      $fazCarrRawSumPerDay[$d] += (float)$min;
      $fazCarrRawCntPerDay[$d] += 1;
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

/* =============================================================================
 * 7) Comercial — HOJE e ONTEM (média diária por SC)
 * ========================================================================== */
$cStmt = pdo()->prepare("
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date BETWEEN :from AND :to
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

$comHojeByDate  = []; // média por dia (Preço Hoje / preco|preco_hoje)
$comOntemByDate = []; // média por dia (Preço Ontem / preco_ontem)

while ($row = $cStmt->fetch(PDO::FETCH_ASSOC)) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'], true) ?: [];
  $vendas = $payload['comercial']['vendas'] ?? [];
  if (!isset($comHojeByDate[$d]))  $comHojeByDate[$d]  = ['sum'=>0.0,'cnt'=>0];
  if (!isset($comOntemByDate[$d])) $comOntemByDate[$d] = ['sum'=>0.0,'cnt'=>0];

  foreach ($vendas as $v) {
    // HOJE
    $precoHojeSC = null;
    if (array_key_exists('preco', $v) && $v['preco'] !== '' && $v['preco'] !== null) {
      $precoHojeSC = (float)$v['preco'];
    } elseif (array_key_exists('preco_hoje', $v) && $v['preco_hoje'] !== '' && $v['preco_hoje'] !== null) {
      $precoHojeSC = (float)$v['preco_hoje'];
    }
    if ($precoHojeSC !== null) {
      $comHojeByDate[$d]['sum'] += $precoHojeSC;
      $comHojeByDate[$d]['cnt'] += 1;
    }

    // ONTEM
    if (array_key_exists('preco_ontem', $v) && $v['preco_ontem'] !== '' && $v['preco_ontem'] !== null) {
      $precoOntemSC = (float)$v['preco_ontem'];
      $comOntemByDate[$d]['sum'] += $precoOntemSC;
      $comOntemByDate[$d]['cnt'] += 1;
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

/* Busca os registros do intervalo (ordem ASC para alinhar com $labels) */
$sqlF18 = "
  SELECT ref_date, payload_json
  FROM safra_entries
  WHERE ref_date BETWEEN :from AND :to
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

/* Mapa por dia => variedade => valor (>0) */
$f18ByDay = [];       // [date][var] = soma do dia
$f18VarSet = [];      // conjunto de variedades encontradas
foreach ($f18Rows as $row) {
  $d = $row['ref_date'];
  $payload = json_decode($row['payload_json'] ?? 'null', true) ?: [];
  $data = payload_bigbag_var($payload);
  if (!is_array($data)) continue;

  if (!isset($f18ByDay[$d])) $f18ByDay[$d] = [];
  // Aceita formatos array OU objeto
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

/* Alinha as séries às datas ISO já usadas pelo dashboard */
ksort($f18ByDay);
$labelsISO  = array_keys($byDay); // já definido adiante, mas precisamos aqui também para alinhar
$f18VarNames = array_keys($f18VarSet);
natcasesort($f18VarNames);
$f18VarNames = array_values($f18VarNames);

/* Inicializa séries com nulls e preenche por data */
$f18SeriesByVar = [];           // assoc: varName => [ ..valores por labelISO.. ]
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

/* Média do período baseada na série TOTAL (não nos dias nulos) */
$sum=0; $cnt=0;
foreach ($f18TotalSeries as $v) { if ($v !== null) { $sum += $v; $cnt++; } }
$f18TotalMean = $cnt>0 ? round($sum/$cnt, 3) : null;

/* =============================================================================
 * 9) Métricas resumo (gerais)
 * ========================================================================== */
$avgOf = function($arr){ $sum=0; $cnt=0; foreach ($arr as $v){ if($v!==null){$sum+=$v;$cnt++;}} return $cnt>0?round($sum/$cnt,3):null; };
$mediaLog   = $avgOf($series['l5']);
$mediaPelada= $avgOf($series['q6_dia']);
$mediaDefeitos=$avgOf($series['q7_dia']);
$mediaUniform =$avgOf($series['q8_dia']);
$mediaCarrLegacy  = $avgOf($series['f_carr_dia']); // legado (não usado no gráfico da fazenda)
$mediaDesc  = $avgOf($series['f_desc_dia']);
$mediaAprov = $avgOf($series['p_aprov_dia']);

/* NOVO: Média correta da Fazenda Carregamento com BRUTOS (todas as entradas/tipos) */
ksort($fazCarrRawSumPerDay);
ksort($fazCarrRawCntPerDay);
$labelsISO  = array_keys($byDay);               // datas ISO das séries gerais
$labelsRawF = array_keys($fazCarrRawSumPerDay); // podem coincidir, mas mantemos independentes

$rawGlobalSum = array_sum($fazCarrRawSumPerDay);
$rawGlobalCnt = array_sum($fazCarrRawCntPerDay);
$mediaFazCarrRaw = ($rawGlobalCnt>0) ? round($rawGlobalSum/$rawGlobalCnt, 3) : null;

/* =============================================================================
 * 10) Séries por tipo (produção e fazenda)
 * ========================================================================== */
$typesProd = array_keys($allTypesProd); sort($typesProd, SORT_NATURAL|SORT_FLAG_CASE);
$typesProdDesc = array_keys($allTypesProdDesc); sort($typesProdDesc, SORT_NATURAL|SORT_FLAG_CASE);
$typesFaz  = array_keys($allTypesFaz ); sort($typesFaz , SORT_NATURAL|SORT_FLAG_CASE);

$seriesProdCarrTipos = []; $seriesProdDescTipos = []; $seriesFazCarrTipos  = [];
foreach ($typesProd as $t)      $seriesProdCarrTipos[$t]  = [];
foreach ($typesProdDesc as $t)  $seriesProdDescTipos[$t]  = [];
foreach ($typesFaz as $t)       $seriesFazCarrTipos[$t]   = [];

/* Preenche séries por dia (média do que entrou no dia para aquele tipo)
   e calcula a “Média diária (entre tipos)” para cada dia, separando carregamento e descarregamento */
$prodCarrDailyMeanSeries = [];
$prodDescDailyMeanSeries = [];

foreach (array_keys($byDay) as $d) {
  // carregamento por tipo
  $carrValsForMean = [];
  foreach ($typesProd as $t) {
    $val = (isset($prodCarrByType[$d][$t]) && $prodCarrByType[$d][$t]['cnt']>0)
      ? round($prodCarrByType[$d][$t]['sum'] / $prodCarrByType[$d][$t]['cnt'], 3)
      : null;
    $seriesProdCarrTipos[$t][] = $val;
    if ($val !== null) $carrValsForMean[] = $val;
  }
  $prodCarrDailyMeanSeries[] = count($carrValsForMean) ? round(array_sum($carrValsForMean)/count($carrValsForMean), 3) : null;

  // descarregamento por tipo
  $descValsForMean = [];
  foreach ($typesProdDesc as $t) {
    $val = (isset($prodDescByType[$d][$t]) && $prodDescByType[$d][$t]['cnt']>0)
      ? round($prodDescByType[$d][$t]['sum'] / $prodDescByType[$d][$t]['cnt'], 3)
      : null;
    $seriesProdDescTipos[$t][] = $val;
    if ($val !== null) $descValsForMean[] = $val;
  }
  $prodDescDailyMeanSeries[] = count($descValsForMean) ? round(array_sum($descValsForMean)/count($descValsForMean), 3) : null;

  // carregamento por tipo (mantido por tipo no gráfico)
  foreach ($typesFaz as $t) {
    $seriesFazCarrTipos[$t][] = (isset($fazCarrByType[$d][$t]) && $fazCarrByType[$d][$t]['cnt']>0)
      ? round($fazCarrByType[$d][$t]['sum'] / $fazCarrByType[$d][$t]['cnt'], 3) : null;
  }
}

/* Médias do período para exibir no meta-texto dos gráficos de produção */
$mediaTMC_period = $avgOf($prodCarrDailyMeanSeries); // carregamento (entre tipos)
$mediaTMD_period = $avgOf($prodDescDailyMeanSeries); // descarregamento (entre tipos)

/* Arrays alinhados aos labels gerais para os BRUTOS de fazenda (sum/cnt por dia) */
$fazCarrRawSumArr = [];
$fazCarrRawCntArr = [];
foreach ($labelsISO as $d) {
  $fazCarrRawSumArr[] = isset($fazCarrRawSumPerDay[$d]) ? round($fazCarrRawSumPerDay[$d], 3) : null;
  $fazCarrRawCntArr[] = isset($fazCarrRawCntPerDay[$d]) ? (int)$fazCarrRawCntPerDay[$d] : null;
}

/* Datas ISO para o client re-filtar sem reload */
$labelsCISO = array_keys($comHojeByDate); // mantida por compat

/* NOVO: médias para Pessoas e Colhedora separadas (usadas nas linhas de média e meta) */
$mediaF17 = $avgOf($series['f17_dia']);
$mediaF19 = $avgOf($series['f19_dia']);

?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Dashboard Geral</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
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
      <?php if (in_array('secComercial', $allowedSections, true)): ?>
      <section id="secComercial" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Comercial • Preço por SC (R$)</h2>
        <p id="com-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartComercialMedia"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secComercialOntem', $allowedSections, true)): ?>
      <section id="secComercialOntem" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Comercial • Preço por SC (Realizado)</h2>
        <p id="com-ontem-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartComercialOntem"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secLogistica', $allowedSections, true)): ?>
      <section id="secLogistica" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Logística • Tempo de transporte (min)</h2>
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
        <h2 class="font-semibold mb-3">Sacos (total) e por colaborador</h2>
        <canvas id="chartProdSacos"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdCarreg', $allowedSections, true)): ?>
      <section id="secProdCarreg" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Carregamento (min)</h2>
        <p id="prod-carr-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdCarreg"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdDesc', $allowedSections, true)): ?>
      <section id="secProdDesc" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Descarregamento (min)</h2>
        <p id="prod-desc-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdDesc"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secProdAprov', $allowedSections, true)): ?>
      <section id="secProdAprov" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Aproveitamento (%)</h2>
        <p id="prod-aprov-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartProdAprov"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazCarreg', $allowedSections, true)): ?>
      <section id="secFazCarreg" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Carregamento (min)</h2>
        <p id="faz-carreg-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaCarreg"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazPessoas', $allowedSections, true)): ?>
      <section id="secFazPessoas" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Pessoas no Campo</h2>
        <p id="faz-pessoas-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaPessoas"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secFazColhedora', $allowedSections, true)): ?>
      <section id="secFazColhedora" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-1">Colhedora</h2>
        <p id="faz-colhedora-meta" class="text-xs text-brand-muted mb-3">—</p>
        <canvas id="chartFazendaColhedora"></canvas>
      </section>
      <?php endif; ?>

      <?php if (in_array('secPie', $allowedSections, true)): ?>
      <section id="secPie" class="card rounded-xl2 bg-brand-surface p-5">
        <h2 class="font-semibold mb-3">Big bag por Variedade</h2>
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

  // ===== NOVO F18 (linhas)
  const f18VarNames     = <?php echo json_encode($f18VarNames, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18SeriesByVar  = <?php echo json_encode($f18SeriesByVar, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalSeries  = <?php echo json_encode($f18TotalSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const f18TotalMean    = <?php echo json_encode($f18TotalMean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  const mediaLog   = <?php echo json_encode($mediaLog, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaDesc  = <?php echo json_encode($mediaDesc, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaAprov = <?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  const mediaPelada    = <?php echo json_encode($mediaPelada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaDefeitos  = <?php echo json_encode($mediaDefeitos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaUniform   = <?php echo json_encode($mediaUniform, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // TIPOS + SÉRIES POR TIPO (produção e fazenda)
  const typesProd     = <?php echo json_encode(array_values($typesProd), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const typesProdDesc = <?php echo json_encode(array_values($typesProdDesc), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const typesFaz      = <?php echo json_encode(array_values($typesFaz),  JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodCarrTipos = <?php echo json_encode($seriesProdCarrTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescTipos = <?php echo json_encode($seriesProdDescTipos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrTipos  = <?php echo json_encode($seriesFazCarrTipos,  JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: média diária (entre tipos) — arrays por dia
  const prodCarrDailyMean = <?php echo json_encode($prodCarrDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const prodDescDailyMean = <?php echo json_encode($prodDescDailyMeanSeries, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaTMC_period   = <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaTMD_period   = <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // Datas ISO gerais
  const labelsISO  = <?php echo json_encode($labelsISO, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== NOVO: brutos da Fazenda Carregamento (sum/cnt por dia) + média do período baseada nos brutos
  const fazCarrRawSum = <?php echo json_encode($fazCarrRawSumArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const fazCarrRawCnt = <?php echo json_encode($fazCarrRawCntArr, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaFazCarrRaw = <?php echo json_encode($mediaFazCarrRaw, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // NOVO: médias separadas Pessoas/Colhedora
  const mediaF17 = <?php echo json_encode($mediaF17, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  const mediaF19 = <?php echo json_encode($mediaF19, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;

  // ===== Estado base e refs dos charts
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

    typesProd: [...typesProd],
    typesProdDesc: [...typesProdDesc],
    typesFaz:  [...typesFaz],
    prodCarrTipos: JSON.parse(JSON.stringify(prodCarrTipos)),
    prodDescTipos: JSON.parse(JSON.stringify(prodDescTipos)),
    fazCarrTipos:  JSON.parse(JSON.stringify(fazCarrTipos)),

    prodCarrDailyMean: [...prodCarrDailyMean],
    prodDescDailyMean: [...prodDescDailyMean],

    // BRUTOS FAZENDA
    fazCarrRawSum: [...fazCarrRawSum],
    fazCarrRawCnt: [...fazCarrRawCnt],

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

  // ====== Catálogo com role explícito
  const ALL_SECTIONS = [
    {id:'secComercial',      label:'Preço por SC (Atual)',               icon:ico.comercial, role:'comercial'},
    {id:'secComercialOntem', label:'Preço por SC (Realizado)',       icon:ico.comercial, role:'comercial'},
    {id:'secLogistica',      label:'Tempo transporte',           icon:ico.logistica, role:'logistica'},
    {id:'secQPelada',        label:'Cebola Pelada (%)',          icon:ico.qualidade, role:'qualidade'},
    {id:'secQDefeitos',      label:'Defeitos (%)',               icon:ico.qualidade, role:'qualidade'},
    {id:'secQUniform',       label:'Uniformidade (%)',           icon:ico.qualidade, role:'qualidade'},
    {id:'secProdSacos',      label:'Sacos & por colaborador',    icon:ico.producao,  role:'producao'},
    {id:'secProdCarreg',     label:'Carregamento por tipo',      icon:ico.producao,  role:'producao'},
    {id:'secProdDesc',       label:'Descarregamento por tipo',   icon:ico.producao,  role:'producao'},
    {id:'secProdAprov',      label:'Aproveitamento (%)',         icon:ico.producao,  role:'producao'},
    {id:'secFazCarreg',      label:'Carregamento por tipo',      icon:ico.fazenda,   role:'fazenda'},
    {id:'secFazPessoas',     label:'Pessoas no Campo',           icon:ico.fazenda,   role:'fazenda'},
    {id:'secFazColhedora',   label:'Colhedora Big Bag',          icon:ico.fazenda,   role:'fazenda'},
    {id:'secPie',            label:'Big Bag por variedade',      icon:ico.fazenda,   role:'fazenda'},
  ];

  const ALLOWED_SEC_IDS = <?php echo json_encode(array_values($allowedSections), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>;
  let selectedSecs       = new Set(<?php echo json_encode(array_values($preSelectedSecs), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  const CATALOG = ALL_SECTIONS.filter(s => ALLOWED_SEC_IDS.includes(s.id));

  // ===== Modal
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

  modalSelAll?.addEventListener('click', ()=>{
    const tmp = new Set(selectedSecs);
    const visibleIds = Array.from(document.querySelectorAll('#modalGridCols .sel-tile')).map(b=>b.dataset.id);
    visibleIds.forEach(id=>tmp.add(id));
    selectedSecs = tmp;
    renderModalColumns();
  });

  modalClear ?.addEventListener('click', ()=>{
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

  // ======= FILTRAGEM DE DATAS NO CLIENTE (sem reload)
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
    let s=0,c=0; for(const v of arr){ if(v!=null && !Number.isNaN(v)){ s+=Number(v); c++; } }
    return c? (s/c) : null;
  }

  const minutesToHHMM = (min) => {
    if (min == null || isNaN(min)) return null;
    const m = Math.round(Number(min));
    const h = Math.floor(m / 60);
    const mm = String(m % 60).padStart(2, '0');
    return `${String(h).padStart(2,'0')}:${mm}`;
  };

  const setMetaMoney = (el, val) => {
    if (!el) return;
    el.textContent = (val == null || isNaN(val))
      ? '—'
      : `• Média no período: R$ ${Number(val).toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 })}`;
  };

  function setMetaMinutes(elId, val){
    const el = document.getElementById(elId);
    if (!el) return;
    if (val==null || isNaN(val)) { el.textContent = '—'; return; }
    const hhmm = minutesToHHMM(val);
    el.textContent = `• Média no período: ${Math.round(val).toLocaleString('pt-BR')} min${hhmm?` (${hhmm})`:''}`;
  }

  function setMetaPercent(elId, val){
    const el = document.getElementById(elId);
    if (!el) return;
    if (val==null || isNaN(val)) { el.textContent = '—'; return; }
    el.textContent = `• Média no período: ${Number(val).toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:2 })} %`;
  }

  function applyDateFilterClient(dFrom, dTo){
    const url = new URL(location.href);
    dFrom ? url.searchParams.set('from', dFrom) : url.searchParams.delete('from');
    dTo   ? url.searchParams.set('to',   dTo)   : url.searchParams.delete('to');
    history.replaceState(null,'', url.toString());

    const keep   = idxRangeByDateISO(BASE.labelsISO,    dFrom, dTo);
    const keepH  = idxRangeByDateISO(BASE.labelsCISO_H, dFrom, dTo);
    const keepO  = idxRangeByDateISO(BASE.labelsCISO_O, dFrom, dTo);

    const L   = sliceByIdx(BASE.labels,  keep);
    const LCH = sliceByIdx(BASE.labelsC_H, keepH);
    const LCO = sliceByIdx(BASE.labelsC_O, keepO);

    const Sfil = {};
    for (const k of Object.keys(BASE.S)) Sfil[k] = sliceByIdx(BASE.S[k], keep);

    // Recalcular médias gerais do recorte
    const mediaLogF   = avgNonNull(Sfil.l5);
    const mediaPelF   = avgNonNull(Sfil.q6_dia);
    const mediaDefF   = avgNonNull(Sfil.q7_dia);
    const mediaUniF   = avgNonNull(Sfil.q8_dia);
    const mediaDescF  = avgNonNull(Sfil.f_desc_dia);
    const mediaAprovF = avgNonNull(Sfil.p_aprov_dia);

    // PRODUÇÃO: médias diárias (entre tipos) re-filtradas
    const prodCarrMeanF = sliceByIdx(BASE.prodCarrDailyMean, keep);
    const prodDescMeanF = sliceByIdx(BASE.prodDescDailyMean, keep);
    const mediaTMCF     = avgNonNull(prodCarrMeanF);
    const mediaTMDF     = avgNonNull(prodDescMeanF);

    // Comercial HOJE
    if (CH.comercial){
      const arr = sliceByIdx(BASE.avgPerSC_H, keepH);
      const med = avgNonNull(arr);
      const mediaArr = med != null ? new Array(LCH.length).fill(med) : new Array(LCH.length).fill(null);
      CH.comercial.data.labels = LCH;
      CH.comercial.data.datasets[0].data = arr;
      CH.comercial.data.datasets[1].data = mediaArr;
      CH.comercial.update();
      setMetaMoney(document.getElementById('com-meta'), med);
    }

    // Comercial ONTEM
    if (CH.comercialOntem){
      const arr = sliceByIdx(BASE.avgPerSC_O, keepO);
      const med = avgNonNull(arr);
      const mediaArr = med != null ? new Array(LCO.length).fill(med) : new Array(LCO.length).fill(null);
      CH.comercialOntem.data.labels = LCO;
      CH.comercialOntem.data.datasets[0].data = arr;
      CH.comercialOntem.data.datasets[1].data = mediaArr;
      CH.comercialOntem.update();
      setMetaMoney(document.getElementById('com-ontem-meta'), med);
    }

    // Logística
    if (CH.logistica){
      CH.logistica.data.labels = L;
      CH.logistica.data.datasets[0].data = Sfil.l5;
      CH.logistica.data.datasets[1].data = new Array(L.length).fill(mediaLogF);
      CH.logistica.update();
      setMetaMinutes('log-meta', mediaLogF);
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
      CH.prodSacos.data.datasets[0].data = Sfil.p15_dia;
      CH.prodSacos.data.datasets[1].data = Sfil.p16_dia;
      CH.prodSacos.update();
    }

    // Produção Carregamento
    if (CH.prodCarreg){
      CH.prodCarreg.data.labels = L;
      for (let i=0;i<BASE.typesProd.length;i++){
        const key = BASE.typesProd[i];
        const serie = sliceByIdx(BASE.prodCarrTipos[key], keep);
        CH.prodCarreg.data.datasets[i].data = serie;
      }
      const idxMean = CH.prodCarreg.data.datasets.length-1;
      CH.prodCarreg.data.datasets[idxMean].data = prodCarrMeanF;
      CH.prodCarreg.update();
      setMetaMinutes('prod-carr-meta', mediaTMCF);
    }

    // Produção Descarregamento
    if (CH.prodDesc){
      CH.prodDesc.data.labels = L;
      for (let i=0;i<BASE.typesProdDesc.length;i++){
        const key = BASE.typesProdDesc[i];
        const serie = sliceByIdx(BASE.prodDescTipos[key], keep);
        CH.prodDesc.data.datasets[i].data = serie;
      }
      const idxMean = CH.prodDesc.data.datasets.length-1;
      CH.prodDesc.data.datasets[idxMean].data = prodDescMeanF;
      CH.prodDesc.update();
      setMetaMinutes('prod-desc-meta', mediaTMDF);
    }

    // Produção Aproveitamento
    if (CH.prodAprov){
      CH.prodAprov.data.labels = L;
      CH.prodAprov.data.datasets[0].data = Sfil.p_aprov_dia;
      CH.prodAprov.data.datasets[1].data = new Array(L.length).fill(mediaAprovF);
      CH.prodAprov.update();
      setMetaPercent('prod-aprov-meta', mediaAprovF);
    }

    // Fazenda Carregamento (brutos)
    if (CH.fazCarr){
      CH.fazCarr.data.labels = L;
      for (let i=0;i<BASE.typesFaz.length;i++){
        const key = BASE.typesFaz[i];
        const serie = sliceByIdx(BASE.fazCarrTipos[key], keep);
        CH.fazCarr.data.datasets[i].data = serie;
      }
      const rawSumF = sliceByIdx(BASE.fazCarrRawSum, keep);
      const rawCntF = sliceByIdx(BASE.fazCarrRawCnt, keep);
      let sum=0, cnt=0;
      for (let i=0;i<rawSumF.length;i++){
        if (rawSumF[i]!=null && rawCntF[i]!=null && rawCntF[i]>0){
          sum += Number(rawSumF[i]);
          cnt += Number(rawCntF[i]);
        }
      }
      const mediaRawF = (cnt>0) ? (sum/cnt) : null;
      CH.fazCarr.data.datasets[CH.fazCarr.data.datasets.length-1].data = new Array(L.length).fill(mediaRawF);
      CH.fazCarr.update();
      setMetaMinutes('faz-carreg-meta', mediaRawF);
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
      if (!datasets.length) return drawMessage(chart, opts);
      const hasAny = datasets.some(ds => {
        const arr = Array.isArray(ds?.data) ? ds.data : [];
        return arr.some(v => v !== null && v !== undefined && !(Number.isNaN(v)));
      });
      if (!hasAny) return drawMessage(chart, opts);
      function drawMessage(chart, opts){
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
  const minutesOpts = {
    ...baseOpts(true),
    plugins: {
      ...baseOpts(true).plugins,
      tooltip:{ callbacks:{ label:(ctx)=>{
        const v = ctx.parsed.y;
        if (v==null) return `${ctx.dataset.label}: -`;
        const m = Math.round(Number(v));
        const h = Math.floor(m/60);
        const mm = String(m%60).padStart(2,'0');
        return `${ctx.dataset.label}: ${Math.round(v).toLocaleString('pt-BR')} min (${String(h).padStart(2,'0')}:${mm})`;
      }}}
    },
    scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Minutos' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
  };
  const typePalette = ['#0072B2','#E69F00','#D55E00','#CC79A7','#56B4E9','#009E73','#F0E442','#000000','#8A2BE2','#FF7F50','#3CB371','#DA70D6'];
  const colorForType = (name, isFaz=false, isDesc=false) => {
    const baseList = isFaz ? typesFaz : (isDesc ? typesProdDesc : typesProd);
    const idx = baseList.indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };
  const colorForVar = (name) => {
    const idx = (BASE.f18VarNames || []).indexOf(name);
    return typePalette[Math.max(0, idx) % typePalette.length];
  };

  // ===== Comercial HOJE
  (function(){
    const el = document.getElementById('chartComercialMedia');
    if (!el) return;
    const mediaPlanaArr = BASE.mediaSC_H != null ? new Array(BASE.labelsC_H.length).fill(BASE.mediaSC_H) : new Array(BASE.labelsC_H.length).fill(null);
    CH.comercial = new Chart(el, {
      data: { labels: BASE.labelsC_H, datasets: [
        mkBar ('Preço por SC (R$)', BASE.avgPerSC_H, THEME.g1),
        mkLine('Média do período', mediaPlanaArr, THEME.g3, 'y', { pointRadius:0, borderWidth:3, borderDash:[6,4] }),
      ]},
      options: {
        ...baseOpts(true),
        plugins:{
          ...baseOpts(true).plugins,
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
            return `${ctx.dataset.label}: R$ ${txt}`;
          }}}
        },
        scales: { y:{ beginAtZero:true, title:{ display:true, text:'R$/SC' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
      }
    });
    setMetaMoney(document.getElementById('com-meta'), BASE.mediaSC_H);
  })();

  // ===== Comercial ONTEM (novo)
  (function(){
    const el = document.getElementById('chartComercialOntem');
    if (!el) return;
    const mediaPlanaArr = BASE.mediaSC_O != null ? new Array(BASE.labelsC_O.length).fill(BASE.mediaSC_O) : new Array(BASE.labelsC_O.length).fill(null);
    CH.comercialOntem = new Chart(el, {
      data: { labels: BASE.labelsC_O, datasets: [
        mkBar ('Preço por SC (Realizado)', BASE.avgPerSC_O, THEME.g2),
        mkLine('Média do período',     mediaPlanaArr,  THEME.g3, 'y', { pointRadius:0, borderWidth:3, borderDash:[6,4] }),
      ]},
      options: {
        ...baseOpts(true),
        plugins:{
          ...baseOpts(true).plugins,
          tooltip:{ callbacks:{ label:(ctx)=>{
            const v = ctx.parsed.y;
            const txt = (v==null?'-':v.toLocaleString('pt-BR',{ minimumFractionDigits:2, maximumFractionDigits:3 }));
            return `${ctx.dataset.label}: R$ ${txt}`;
          }}}
        },
        scales: { y:{ beginAtZero:true, title:{ display:true, text:'R$/SC' } }, x:{ ticks:{ color: hexToRgba(THEME.text,.7) } } }
      }
    });
    setMetaMoney(document.getElementById('com-ontem-meta'), BASE.mediaSC_O);
  })();

  // ===== Logística
  (function(){
    const el = document.getElementById('chartLogistica');
    if (!el) return;
    CH.logistica = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Tempo de transporte (min)', S.l5, THEME.g2, 'y'),
        mkLine('Média no período (min)', new Array(labels.length).fill(<?php echo json_encode($mediaLog, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
      ]},
      options: minutesOpts
    });
    setMetaMinutes('log-meta', <?php echo json_encode($mediaLog, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
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
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaPelada, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaDefeitos, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaUniform, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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
        mkLine ('Sacos por colaborador', S.p15_dia, THEME.yellow, 'y'),
        mkBar ('Sacos beneficiados (dia)',     S.p16_dia, THEME.g2, 'y1'),
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

  // ===== Produção: Carregamento
  (function(){
    const el = document.getElementById('chartProdCarreg');
    if (!el) return;
    CH.prodCarreg = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...minutesOpts, plugins:{ ...minutesOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });
    const ds = typesProd.map(k => ({ ...mkLine(k, (prodCarrTipos[k]||[]), (colorForType(k, false, false)), 'y') }));
    ds.push(mkLine('Média diária (entre tipos)', prodCarrDailyMean, THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));
    CH.prodCarreg.data.datasets = ds; CH.prodCarreg.update();
    setMetaMinutes('prod-carr-meta', <?php echo json_encode($mediaTMC_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  // ===== Produção: Descarregamento
  (function(){
    const el = document.getElementById('chartProdDesc');
    if (!el) return;
    CH.prodDesc = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...minutesOpts, plugins:{ ...minutesOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });
    const ds = typesProdDesc.map(k => ({ ...mkLine(k, (prodDescTipos[k]||[]), (colorForType(k, false, true)), 'y') }));
    ds.push(mkLine('Média diária (entre tipos)', prodDescDailyMean, THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));
    CH.prodDesc.data.datasets = ds; CH.prodDesc.update();
    setMetaMinutes('prod-desc-meta', <?php echo json_encode($mediaTMD_period, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);
  })();

  // ===== Produção: Aproveitamento
  (function(){
    setMetaPercent('prod-aprov-meta', <?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>);

    const el = document.getElementById('chartProdAprov');
    if (!el) return;
    CH.prodAprov = new Chart(el, {
      data:{ labels, datasets:[
        mkLine('Aproveitamento (%)', S.p_aprov_dia, THEME.g2, 'y'),
        mkLine('Média no período (%)', new Array(labels.length).fill(<?php echo json_encode($mediaAprov, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES); ?>), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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

  // ===== Fazenda Carregamento (brutos)
  (function(){
    const el = document.getElementById('chartFazendaCarreg');
    if (!el) return;
    CH.fazCarr = new Chart(el, { data:{ labels, datasets:[] }, options:{ ...minutesOpts, plugins:{ ...minutesOpts.plugins, legend:{ position:'bottom', labels:{ boxWidth:12 } } } } });
    const ds = typesFaz.map(k => ({ ...mkLine(k, (fazCarrTipos[k]||[]), (colorForType(k, true, false)), 'y') }));
    ds.push(mkLine('Média no período (min)', new Array(labels.length).fill(mediaFazCarrRaw), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }));
    CH.fazCarr.data.datasets = ds; CH.fazCarr.update();
    setMetaMinutes('faz-carreg-meta', mediaFazCarrRaw);
  })();

  // ===== Pessoas (F17)
  (function(){
    const el = document.getElementById('chartFazendaPessoas');
    if (!el) return;
    CH.fazPessoas = new Chart(el, {
      data:{ labels, datasets:[
        mkBar ('F17 Pessoas/dia (bruto)', S.f17_dia, THEME.g3, 'y'),
        mkLine('Média no período', new Array(labels.length).fill(mediaF17), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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
        mkLine('Média no período', new Array(labels.length).fill(mediaF19), THEME.g1, 'y', { pointRadius:0, borderDash:[6,4], borderWidth:3 }),
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

</script>
</body>
</html>
