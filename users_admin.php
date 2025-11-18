<?php
// /boden/users_admin.php
// Administração de usuários: criação, listagem e edição com papéis (RBAC).
// Requer: auth.php (pdo(), require_auth(), user_can(), csrf_*)

require_once __DIR__ . '/auth.php';
require_auth();
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/navbar.php'; // carrega wrappers e a função de render
require_once __DIR__.'/ui/datepicker.php';

// Só quem tiver permissão "manage" no recurso "admin_users" (ou papel admin) acessa
if (!user_can('manage', 'admin_users')) {
  http_response_code(403);
  echo "<h1 style='font-family:system-ui,sans-serif'>403 • Sem permissão</h1>";
  exit;
}

// flash helper
function flash($msg=null) {
  if ($msg!==null) { $_SESSION['flash']=$msg; return; }
  if (isset($_SESSION['flash'])) { $m=$_SESSION['flash']; unset($_SESSION['flash']); return $m; }
  return null;
}

// carregar papéis disponíveis
$roles = pdo()->query("SELECT id, slug, name FROM roles ORDER BY name ASC")->fetchAll(PDO::FETCH_ASSOC);

// tratar POST (criar usuário / atualizar usuário)
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $action = $_POST['action'] ?? '';
  if (!csrf_check($_POST['csrf'] ?? '')) {
    $errors[] = 'Sessão expirada. Recarregue a página e tente novamente.';
  } else if ($action === 'create') {
    $name  = trim($_POST['name']  ?? '');
    $email = trim($_POST['email'] ?? '');
    $pass  = (string)($_POST['password'] ?? '');
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $role_ids = array_map('intval', array_filter((array)($_POST['roles'] ?? [])));

    if ($name==='')  $errors[] = 'Nome é obrigatório.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'E-mail inválido.';
    if (strlen($pass) < 8) $errors[] = 'Senha deve ter pelo menos 8 caracteres.';
    if (!$role_ids)  $errors[] = 'Selecione pelo menos um papel (role).';

    // e-mail único
    $st = pdo()->prepare("SELECT 1 FROM users WHERE email=:e LIMIT 1");
    $st->execute([':e'=>$email]);
    if ($st->fetch()) $errors[] = 'Já existe um usuário com este e-mail.';

    if (!$errors) {
      $hash = password_hash($pass, PASSWORD_DEFAULT);
      pdo()->beginTransaction();
      try {
        $ins = pdo()->prepare("INSERT INTO users (name,email,pass_hash,is_active) VALUES (:n,:e,:h,:a)");
        $ins->execute([':n'=>$name, ':e'=>$email, ':h'=>$hash, ':a'=>$is_active]);
        $uid = (int)pdo()->lastInsertId();

        // vincular papéis
        $insR = pdo()->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (:u,:r)");
        foreach ($role_ids as $rid) { $insR->execute([':u'=>$uid, ':r'=>$rid]); }

        pdo()->commit();
        flash('Usuário criado com sucesso.');
        header('Location: '.$_SERVER['REQUEST_URI']);
        exit;
      } catch (Throwable $ex) {
        pdo()->rollBack();
        $errors[] = 'Erro ao gravar no banco: '.$ex->getMessage();
      }
    }
  } else if ($action === 'update') {
    // Atualização via modal
    $uid   = (int)($_POST['id'] ?? 0);
    $name  = trim($_POST['name']  ?? '');
    $email = trim($_POST['email'] ?? '');
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $newpass   = (string)($_POST['new_password'] ?? '');
    $role_ids  = array_map('intval', array_filter((array)($_POST['roles'] ?? [])));

    if ($uid<=0) $errors[] = 'Usuário inválido.';
    if ($name==='')  $errors[] = 'Nome é obrigatório.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'E-mail inválido.';
    if ($newpass !== '' && strlen($newpass) < 8) $errors[] = 'Nova senha deve ter pelo menos 8 caracteres.';
    if (!$role_ids)  $errors[] = 'Selecione pelo menos um papel (role).';

    // e-mail único (ignorando o próprio id)
    $st = pdo()->prepare("SELECT 1 FROM users WHERE email=:e AND id<>:id LIMIT 1");
    $st->execute([':e'=>$email, ':id'=>$uid]);
    if ($st->fetch()) $errors[] = 'Já existe outro usuário com este e-mail.';

    if (!$errors) {
      pdo()->beginTransaction();
      try {
        // monta update dinâmico (com ou sem troca de senha)
        if ($newpass !== '') {
          $hash = password_hash($newpass, PASSWORD_DEFAULT);
          $up = pdo()->prepare("UPDATE users SET name=:n, email=:e, is_active=:a, pass_hash=:h WHERE id=:id");
          $up->execute([':n'=>$name, ':e'=>$email, ':a'=>$is_active, ':h'=>$hash, ':id'=>$uid]);
        } else {
          $up = pdo()->prepare("UPDATE users SET name=:n, email=:e, is_active=:a WHERE id=:id");
          $up->execute([':n'=>$name, ':e'=>$email, ':a'=>$is_active, ':id'=>$uid]);
        }

        // zera e recria vínculos de roles
        $del = pdo()->prepare("DELETE FROM user_roles WHERE user_id=:u");
        $del->execute([':u'=>$uid]);

        $insR = pdo()->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (:u,:r)");
        foreach ($role_ids as $rid) { $insR->execute([':u'=>$uid, ':r'=>$rid]); }

        pdo()->commit();
        flash('Usuário atualizado com sucesso.');
        header('Location: '.$_SERVER['REQUEST_URI']);
        exit;
      } catch (Throwable $ex) {
        pdo()->rollBack();
        $errors[] = 'Erro ao atualizar registro: '.$ex->getMessage();
      }
    }
  }
}

// listar usuários + papéis
$users = pdo()->query("
  SELECT u.id, u.name, u.email, u.is_active, u.created_at
  FROM users u
  ORDER BY u.created_at DESC, u.id DESC
")->fetchAll(PDO::FETCH_ASSOC);

// map de roles por usuário (ids e nomes)
$rolesIdsByUser = [];
$rolesNamesByUser = [];
if ($users) {
  $ids = implode(',', array_map('intval', array_column($users,'id')));
  // ids
  $mapIds = pdo()->query("
    SELECT ur.user_id, ur.role_id
    FROM user_roles ur
    WHERE ur.user_id IN ($ids)
    ORDER BY ur.role_id
  ")->fetchAll(PDO::FETCH_ASSOC);
  foreach ($mapIds as $row) {
    $rolesIdsByUser[(int)$row['user_id']][] = (int)$row['role_id'];
  }
  // nomes
  $mapNames = pdo()->query("
    SELECT ur.user_id, r.name
    FROM user_roles ur
    JOIN roles r ON r.id=ur.role_id
    WHERE ur.user_id IN ($ids)
    ORDER BY r.name
  ")->fetchAll(PDO::FETCH_ASSOC);
  foreach ($mapNames as $row) {
    $rolesNamesByUser[(int)$row['user_id']][] = (string)$row['name'];
  }
}

$flash = flash();
?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Safra Cebola 25/26</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
  <link rel="stylesheet" href="./dist/styles.css">
  <style>
    body { background:#F9FAFB; }
    .card { border:1px solid #E5E7EB; box-shadow:0 6px 18px rgba(0,0,0,.05); }
    .modal-overlay{ position:fixed; inset:0; background:rgba(17,24,39,.45); -webkit-backdrop-filter:blur(10px); backdrop-filter:blur(10px); z-index:50; }
    .modal-card{ width:98vw; max-width:720px; max-height:96vh; overflow:auto; }
  </style>
  <?php render_datepicker_assets(); ?>
</head>
<body class="text-gray-800">
  <!-- NAVBAR -->
  <?php render_boden_navbar('users'); ?>

  <main class="max-w-6xl mx-auto p-6 lg:p-8 space-y-8">
    <header class="flex items-center justify-between">
      <h1 class="text-2xl font-bold">Usuários</h1>
    </header>

    <?php if ($flash): ?>
      <div class="bg-green-50 border border-green-200 text-green-800 rounded p-3">
        <?=htmlspecialchars($flash)?>
      </div>
    <?php endif; ?>

    <?php if ($errors): ?>
      <div class="bg-red-50 border border-red-200 text-red-800 rounded p-3">
        <ul class="list-disc ml-5">
          <?php foreach ($errors as $e): ?><li><?=htmlspecialchars($e)?></li><?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <!-- Form de criação -->
    <section class="card bg-white rounded-xl p-6">
      <h2 class="text-lg font-semibold mb-4">Criar usuário</h2>
      <form method="POST" class="grid gap-4 md:grid-cols-2">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="csrf" value="<?=htmlspecialchars(csrf_token())?>">

        <div class="md:col-span-1">
          <label class="text-sm text-gray-600">Nome</label>
          <input name="name" required class="mt-1 w-full border rounded-lg px-3 py-2" placeholder="Nome completo">
        </div>

        <div class="md:col-span-1">
          <label class="text-sm text-gray-600">E-mail</label>
          <input type="email" name="email" required class="mt-1 w-full border rounded-lg px-3 py-2" placeholder="email@empresa.com">
        </div>

        <div class="md:col-span-1">
          <label class="text-sm text-gray-600">Senha</label>
          <input type="password" name="password" required minlength="8" class="mt-1 w-full border rounded-lg px-3 py-2" placeholder="Min. 8 caracteres">
        </div>

        <div class="md:col-span-1">
          <label class="text-sm text-gray-600">Status</label>
          <div class="mt-2">
            <label class="inline-flex items-center gap-2">
              <input type="checkbox" name="is_active" class="h-4 w-4" checked>
              <span>Ativo</span>
            </label>
          </div>
        </div>

        <div class="md:col-span-2">
          <label class="text-sm text-gray-600">Papéis (roles)</label>
          <div class="mt-2 grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
            <?php foreach ($roles as $r): ?>
              <label class="border rounded-lg px-3 py-2 flex items-center gap-2">
                <input type="checkbox" name="roles[]" value="<?=$r['id']?>" class="h-4 w-4">
                <span class="text-sm"><?=htmlspecialchars($r['name'])?> <span class="text-gray-400">(<?=htmlspecialchars($r['slug'])?>)</span></span>
              </label>
            <?php endforeach; ?>
          </div>
        </div>

        <div class="md:col-span-2 flex justify-end">
          <button class="px-4 py-2 rounded-lg bg-[#5FB141] text-white font-semibold hover:bg-green-600">Criar usuário</button>
        </div>
      </form>
    </section>

    <!-- Tabela de usuários -->
    <section class="card bg-white rounded-xl p-6">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-lg font-semibold">Usuários existentes</h2>
        <p class="text-sm text-gray-500"><?=count($users)?> cadastro(s)</p>
      </div>

      <div class="overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead>
            <tr class="text-left text-gray-600">
              <th class="py-2 pr-4">Nome</th>
              <th class="py-2 pr-4">E-mail</th>
              <th class="py-2 pr-4">Papéis</th>
              <th class="py-2 pr-4">Status</th>
              <th class="py-2 pr-4">Criado em</th>
              <th class="py-2 pr-4">Ações</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($users as $u): ?>
              <tr class="border-t align-top">
                <td class="py-2 pr-4"><?=htmlspecialchars($u['name'])?></td>
                <td class="py-2 pr-4"><?=htmlspecialchars($u['email'])?></td>
                <td class="py-2 pr-4">
                  <?php
                    $rs = $rolesNamesByUser[$u['id']] ?? [];
                    echo $rs ? htmlspecialchars(implode(', ', $rs)) : '<span class="text-gray-400">—</span>';
                  ?>
                </td>
                <td class="py-2 pr-4">
                  <?php if ($u['is_active']): ?>
                    <span class="px-2 py-0.5 rounded-full text-xs bg-green-100 text-green-800">ativo</span>
                  <?php else: ?>
                    <span class="px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-600">inativo</span>
                  <?php endif; ?>
                </td>
                <td class="py-2 pr-4"><?=htmlspecialchars(date('d/m/Y H:i', strtotime($u['created_at'])))?></td>
                <td class="py-2 pr-4">
                  <button
                    class="px-3 py-1.5 rounded-lg border bg-white hover:bg-gray-50"
                    data-edit
                    data-id="<?= (int)$u['id'] ?>"
                    data-name="<?= htmlspecialchars($u['name'], ENT_QUOTES) ?>"
                    data-email="<?= htmlspecialchars($u['email'], ENT_QUOTES) ?>"
                    data-active="<?= (int)$u['is_active'] ?>"
                    data-roles='<?= json_encode($rolesIdsByUser[$u['id']] ?? []) ?>'
                  >Editar</button>
                </td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </section>
          <footer class="mt-12 pt-8 border-t border-brand-line text-center">
      <p class="text-sm text-brand-muted">Powered by TI - Grupo W3 © <?php echo date('Y'); ?></p>
    </footer>
  </main>

  <!-- MODAL DE EDIÇÃO -->
  <div id="editModal" class="hidden">
    <div class="modal-overlay"></div>
    <div class="fixed inset-0 flex items-center justify-center z-50 p-3 sm:p-6">
      <div class="modal-card card bg-white rounded-xl p-5 relative">
        <button id="editClose" class="absolute right-3 top-3 text-gray-500 hover:text-gray-700 text-lg" aria-label="Fechar">✕</button>
        <h3 class="text-lg font-semibold mb-4">Editar usuário</h3>

        <form id="editForm" method="POST" class="grid gap-4 md:grid-cols-2">
          <input type="hidden" name="action" value="update">
          <input type="hidden" name="csrf" value="<?=htmlspecialchars(csrf_token())?>">
          <input type="hidden" name="id" id="f_id">

          <div class="md:col-span-1">
            <label class="text-sm text-gray-600">Nome</label>
            <input name="name" id="f_name" required class="mt-1 w-full border rounded-lg px-3 py-2">
          </div>

          <div class="md:col-span-1">
            <label class="text-sm text-gray-600">E-mail</label>
            <input type="email" name="email" id="f_email" required class="mt-1 w-full border rounded-lg px-3 py-2">
          </div>

          <div class="md:col-span-1">
            <label class="text-sm text-gray-600">Nova senha (opcional)</label>
            <input type="password" name="new_password" id="f_new_password" minlength="8" class="mt-1 w-full border rounded-lg px-3 py-2" placeholder="Deixe em branco para manter">
          </div>

          <div class="md:col-span-1">
            <label class="text-sm text-gray-600">Status</label>
            <div class="mt-2">
              <label class="inline-flex items-center gap-2">
                <input type="checkbox" name="is_active" id="f_is_active" class="h-4 w-4">
                <span>Ativo</span>
              </label>
            </div>
          </div>

          <div class="md:col-span-2">
            <label class="text-sm text-gray-600">Papéis (roles)</label>
            <div id="rolesBox" class="mt-2 grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
              <?php foreach ($roles as $r): ?>
                <label class="border rounded-lg px-3 py-2 flex items-center gap-2">
                  <input type="checkbox" name="roles[]" value="<?=$r['id']?>" class="h-4 w-4 role-check">
                  <span class="text-sm"><?=htmlspecialchars($r['name'])?> <span class="text-gray-400">(<?=htmlspecialchars($r['slug'])?>)</span></span>
                </label>
              <?php endforeach; ?>
            </div>
          </div>

          <div class="md:col-span-2 flex justify-end gap-2">
            <button type="button" id="editCancel" class="px-4 py-2 rounded-lg border bg-white hover:bg-gray-50">Cancelar</button>
            <button class="px-4 py-2 rounded-lg bg-[#5FB141] text-white font-semibold hover:bg-green-600">Salvar alterações</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <script>
    (function(){
      const $ = (sel,ctx=document)=>ctx.querySelector(sel);
      const $$= (sel,ctx=document)=>Array.from(ctx.querySelectorAll(sel));

      const modal = $('#editModal');
      const closeBtns = ['#editClose','#editCancel'].map(id=>$(id));
      function openModal(){ modal.classList.remove('hidden'); document.body.style.overflow='hidden'; }
      function closeModal(){ modal.classList.add('hidden'); document.body.style.overflow=''; $('#f_new_password').value=''; }

      closeBtns.forEach(btn=> btn && btn.addEventListener('click', closeModal));
      modal.addEventListener('click', (e)=>{ if(e.target.classList.contains('modal-overlay')) closeModal(); });
      document.addEventListener('keydown', (e)=>{ if(e.key==='Escape') closeModal(); });

      // Preenche o formulário do modal
      function fillModalFromBtn(btn){
        $('#f_id').value    = btn.dataset.id || '';
        $('#f_name').value  = btn.dataset.name || '';
        $('#f_email').value = btn.dataset.email || '';
        $('#f_is_active').checked = (btn.dataset.active === '1');

        // zera os roles
        $$('.role-check').forEach(ch=>{ ch.checked=false; });
        try{
          const selected = JSON.parse(btn.dataset.roles || '[]');
          const set = new Set(selected.map(Number));
          $$('.role-check').forEach(ch=>{
            if(set.has(Number(ch.value))) ch.checked = true;
          });
        }catch(_){}
      }

      // Ação: abrir modal ao clicar em "Editar"
      $$('[data-edit]').forEach(btn=>{
        btn.addEventListener('click', ()=>{
          fillModalFromBtn(btn);
          openModal();
        });
      });
    })();
  </script>
</body>
</html>
