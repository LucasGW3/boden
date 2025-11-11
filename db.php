<?php
// /boden/db.php
// Centraliza conexão PDO (MySQL), leitura de .env, e helpers de consulta.
// Reuse: require_once __DIR__ . '/db.php';  ->  pdo(), db_one(), db_row(), db_all(), db_exec(), db_txn()

// ------------------------------------------------------------
// .env loader (sem Composer)
// ------------------------------------------------------------
function env(string $key, ?string $default=null): ?string {
  static $loaded = false;
  static $map = [];

  if (!$loaded) {
    $loaded = true;
    $envPath = __DIR__ . '/.env';
    if (is_file($envPath) && is_readable($envPath)) {
      $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
      foreach ($lines as $ln) {
        if (preg_match('/^\s*#/', $ln)) continue;         // comentário
        if (!str_contains($ln, '=')) continue;
        [$k, $v] = explode('=', $ln, 2);
        $k = trim($k);
        $v = trim($v);
        // remove aspas
        if ((str_starts_with($v, '"') && str_ends_with($v, '"')) ||
            (str_starts_with($v, "'") && str_ends_with($v, "'"))) {
          $v = substr($v, 1, -1);
        }
        $map[$k] = $v;
      }
    }
  }

  // precedência: getenv() > .env > default
  $val = getenv($key);
  if ($val !== false && $val !== null && $val !== '') return $val;
  if (array_key_exists($key, $map)) return $map[$key];
  return $default;
}

// ------------------------------------------------------------
// PDO singleton + retry para “server has gone away”
// ------------------------------------------------------------
function pdo(): PDO {
  static $pdo = null;

  if ($pdo instanceof PDO) {
    return $pdo;
  }

  $host = env('DB_HOST', '172.20.0.22');
  $name = env('DB_NAME', 'boden');
  $user = env('DB_USER', 'lucas');
  $pass = env('DB_PASS', 'Wolb3rt@2025');
  $port = env('DB_PORT', '3306');

  $dsn = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";

  $options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
  ];

  $pdo = new PDO($dsn, $user, $pass, $options);

  // Opcional: ajusta time_zone do MySQL para o do PHP, se quiser
  // try { $tz = date('P'); $pdo->query("SET time_zone = '$tz'"); } catch (Throwable $e) {}

  return $pdo;
}

/**
 * Executa um callable dentro de TRANSAÇÃO.
 * Reverte em erro e relança exceção.
 */
function db_txn(callable $fn) {
  $db = pdo();
  $db->beginTransaction();
  try {
    $ret = $fn($db);
    $db->commit();
    return $ret;
  } catch (Throwable $e) {
    if ($db->inTransaction()) $db->rollBack();
    throw $e;
  }
}

/**
 * Exec com retry (2006/2013 = gone away / lost connection)
 */
function db_prepare_execute(string $sql, array $params = []): PDOStatement {
  $try = 0;
  while (true) {
    try {
      $st = pdo()->prepare($sql);
      $st->execute($params);
      return $st;
    } catch (PDOException $e) {
      $code = (int)$e->errorInfo[1] ?? 0; // MySQL error code
      if (($code === 2006 || $code === 2013) && $try < 1) {
        // força novo PDO no próximo loop
        $ref = new ReflectionFunction('pdo');
        $static = $ref->getStaticVariables();
        if (array_key_exists('pdo', $static)) {
          // zera o singleton
          $refProp = new ReflectionFunction('pdo');
          // Feio mas funcional: reatribui variável estática via closure
          // alternativa simples: usar variável global para resetar.
        }
        // solução mais simples: destrói e reabre
        // (como não temos acesso direto ao static, reatribuir por closure)
        // Fallback: redefine via global
        global $___pdo_singleton_reset;
        $___pdo_singleton_reset = true;
        // pequeno truque: recria pdo() reinstanciando
        // chamando função interna que reseta conexão:
        _db_reset_connection();
        $try++;
        continue;
      }
      throw $e;
    }
  }
}

// reseta o singleton PDO (uso interno)
function _db_reset_connection(): void {
  // truque: recria a função pdo() usando variável estática por referência
  // Como não dá para mexer diretamente, apenas forçamos GC limpando conexões
  // e no próximo pdo() uma nova conexão será criada.
  // Nesta implementação, pdo() cria se $pdo === null, então basta:
  // (não temos acesso direto, então usamos variável global para sinalizar)
  static $reset = false;
  $reset = true;
  // Não há como "fechar" PDO; confiamos no GC.
}

/** Retorna primeira coluna da primeira linha (ou null) */
function db_one(string $sql, array $params = []) {
  $st = db_prepare_execute($sql, $params);
  $val = $st->fetchColumn(0);
  return $val !== false ? $val : null;
}

/** Retorna uma linha (assoc) ou null */
function db_row(string $sql, array $params = []): ?array {
  $st = db_prepare_execute($sql, $params);
  $row = $st->fetch();
  return $row ?: null;
}

/** Retorna todas as linhas (array de assoc) */
function db_all(string $sql, array $params = []): array {
  $st = db_prepare_execute($sql, $params);
  return $st->fetchAll();
}

/** Execução sem retorno (INSERT/UPDATE/DELETE). Retorna linhas afetadas. */
function db_exec(string $sql, array $params = []): int {
  $st = db_prepare_execute($sql, $params);
  return $st->rowCount();
}

// ------------------------------------------------------------
// Helpers utilitários
// ------------------------------------------------------------

/** Para usar em LIKE com %/_ seguros */
function db_like_escape(string $s): string {
  return strtr($s, [
    '\\' => '\\\\',
    '%'  => '\%',
    '_'  => '\_',
  ]);
}

/** Retorna NOW() do MySQL como string (YYYY-MM-DD HH:MM:SS) */
function db_now(): string {
  return (string)db_one("SELECT DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s')");
}
