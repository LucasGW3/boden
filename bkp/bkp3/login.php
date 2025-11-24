<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';

$erro = '';

if ($_SERVER['REQUEST_METHOD']==='POST') {
  if (!csrf_check($_POST['csrf'] ?? '')) {
    $erro = 'Sessão expirada. Tente novamente.'; 
  } else {
    $email = trim($_POST['email'] ?? '');
    $pass  = (string)($_POST['password'] ?? '');
    if (auth_login($email, $pass)) {
      $next = $_GET['next'] ?? './index.php';
      header('Location: '.$next); exit;
    } else {
      $erro = 'Credenciais inválidas.';
    }
  }
}
?>
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Boden - Login</title>
  <link href="https://fonts.googleapis.com/css2?family=Cabin:ital,wght@0,400..700;1,400..700&family=Josefin+Sans:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <link rel="icon" type="image/png" sizes="96x96" href="./favicon-96x96.png">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.mask/1.14.16/jquery.mask.min.js"></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="style_index.css">
</head>
<body>
    <div class="container py-5">
    <div class="row justify-content-center">
      <div class="col-md-8 col-lg-6">
        <img src="./boden.png" alt="Logo" class="logo">
        <div class="card login-card">
          <div class="card-header card-header-custom text-white text-center position-relative">
            <h3 class="Titulo">Safra de Cebola</h3>
            <img src="./logo w3.png" alt="Logo" class="logo-cortada">
          </div>
            <div class="card-body p-4">
            <?php if (!empty($erro)): ?>
              <div class="alert alert-danger"><?= htmlspecialchars($erro) ?></div>
            <?php endif; ?>
            <form method="POST" id="loginForm">
              <div class="mb-3">
                <label for="usuario" class="form-label">Usuário:</label>
                <input type="text" class="form-control" type="email" name="email" required autofocus placeholder="Digite seu usuário" required/>
              </div>
              <div class="mb-3">
                <label for="senha" class="form-label">Senha:</label>
                <input type="password" class="form-control" name="password" placeholder="Digite sua senha" required />
              </div>
              <div class="d-grid gap-2">
                <input type="hidden" name="csrf" value="<?=htmlspecialchars(csrf_token())?>">
                <button class="btn btn-portal btn-lg">
                  Acessar Sistema
                </button>
              </div>
            </form>
          </div>
        </div>
        <footer class="mt-12 pt-8 border-t border-brand-line text-center">
      <p class="text-sm text-brand-muted">Powered by TI - Grupo W3 © <?php echo date('Y'); ?></p>
    </footer>
      </div>
    </div>
  </div>
  <!-- Loader -->
<div id="loader" style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;display:flex;justify-content:center;align-items:center;">
  <div class="spinner-border text-primary" role="status">
    <span class="visually-hidden">Carregando...</span>
  </div>
</div>
  <script>
  $(document).ready(function(){
    $('.card.login-card').addClass('aparecer');
    $('.logo').addClass('aparecer');
  });
</script>
<script>
  window.addEventListener('load', function() {
    const loader = document.getElementById('loader');
    if (loader) {
      loader.style.display = 'none';
    }
  });
</script>
</body>
</html>
