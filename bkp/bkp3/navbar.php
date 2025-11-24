<?php
/**
 * navbar.php — Navbar Boden (estilo Productor, sem Bootstrap)
 *
 * Uso:
 *   require_once __DIR__ . '/navbar.php';
 *   render_boden_navbar(); // autodetecta a página ativa
 *   // ou: render_boden_navbar('form'|'dashboard'|'variedade'|'users');
 */

require_once __DIR__ . '/auth.php';
require_auth();
require_once __DIR__ . '/db.php';

if (!function_exists('h')) {
  function h(?string $v): string { return htmlspecialchars($v ?? '', ENT_QUOTES, 'UTF-8'); }
}

/* ------------------------ CSRF fallback ------------------------ */
if (!function_exists('csrf_token')) {
  function csrf_token(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
  }
}

/* --------------------- Wrappers seguros base ------------------- */
if (!function_exists('user_can_safe')) {
  function user_can_safe(...$args): ?bool {
    if (!function_exists('user_can')) return null;
    try {
      $rf = new ReflectionFunction('user_can');
      $min = $rf->getNumberOfRequiredParameters();
      if (count($args) < $min) return null;
      return (bool) user_can(...$args);
    } catch (Throwable $e) { return null; }
  }
}
if (!function_exists('can_view_dashboard_var_safe')) {
  function can_view_dashboard_var_safe(): bool {
    try { if (function_exists('can_view_dashboard_var')) return (bool) can_view_dashboard_var(); } catch (Throwable $e) {}
    return false;
  }
}
if (!function_exists('can_manage_users_safe')) {
  function can_manage_users_safe(): bool {
    try { if (function_exists('can_manage_users')) return (bool) can_manage_users(); } catch (Throwable $e) {}
    return false;
  }
}

/* ----------------- Helpers usuário/roles ---------------- */
if (!function_exists('current_user_display_name')) {
  function current_user_display_name(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $name = trim((string)($_SESSION['uname'] ?? ''));
    if ($name !== '') return $name;
    $uid = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;
    if ($uid > 0) {
      try {
        $st = pdo()->prepare("SELECT COALESCE(NULLIF(name,''), email) AS disp FROM users WHERE id=:id");
        $st->execute([':id'=>$uid]);
        $val = trim((string)$st->fetchColumn());
        if ($val !== '') { $_SESSION['uname'] = $val; return $val; }
      } catch (Throwable $e) {}
    }
    return trim((string)($_SESSION['uemail'] ?? ''));
  }
}
if (!function_exists('current_user_email')) {
  function current_user_email(): string {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $email = trim((string)($_SESSION['uemail'] ?? ''));
    if ($email !== '') return $email;
    $uid = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;
    if ($uid > 0) {
      try {
        $st = pdo()->prepare("SELECT email FROM users WHERE id = :id");
        $st->execute([':id' => $uid]);
        $val = trim((string)$st->fetchColumn());
        if ($val !== '') { $_SESSION['uemail'] = $val; return $val; }
      } catch (Throwable $e) {}
    }
    return '';
  }
}

if (!function_exists('normalize_role_name')) {
  function normalize_role_name(string $r): string {
    $r0 = mb_strtolower(trim($r),'UTF-8');
    $aliasesAdmin = ['admin','administrator','administrador','root','superadmin','super-admin','ti_admin'];
    $aliasesCom   = ['comercial','comércio','comercio','vendas','sales','com'];
    if (in_array($r0,$aliasesAdmin,true)) return 'Admin';
    if (in_array($r0,$aliasesCom,true))   return 'Comercial';
    return mb_convert_case($r0, MB_CASE_TITLE_SIMPLE, 'UTF-8');
  }
}
if (!function_exists('normalize_roles')) {
  function normalize_roles(array $roles): array {
    $out = [];
    foreach ($roles as $r) { $n = normalize_role_name((string)$r); if ($n!=='') $out[$n]=true; }
    return array_keys($out);
  }
}
if (!function_exists('session_roles_guess')) {
  function session_roles_guess(): array {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $cands=[];
    foreach(['roles','uroles','user_roles'] as $k) if(!empty($_SESSION[$k]) && is_array($_SESSION[$k])) $cands=array_merge($cands,$_SESSION[$k]);
    foreach(['roles','uroles','user_roles','role','perfil','profile','cargo'] as $k){
      if(!empty($_SESSION[$k]) && !is_array($_SESSION[$k])) $cands=array_merge($cands,array_map('trim',explode(',',(string)$_SESSION[$k])));
    }
    foreach(['is_admin','admin','isAdmin'] as $k) if(!empty($_SESSION[$k])) $cands[]='Admin';
    foreach(['is_comercial','comercial','isComercial','is_sales'] as $k) if(!empty($_SESSION[$k])) $cands[]='Comercial';
    return normalize_roles($cands);
  }
}
if (!function_exists('current_user_roles')) {
  function current_user_roles(): array {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    if (isset($_SESSION['uroles']) && is_array($_SESSION['uroles'])) return normalize_roles($_SESSION['uroles']);
    $sessRoles = session_roles_guess();
    $uid = isset($_SESSION['uid']) ? (int)$_SESSION['uid'] : 0;
    $dbRoles=[];
    if ($uid>0){
      try{
        $st=pdo()->prepare("SELECT roles,role,is_admin,is_comercial FROM users WHERE id=:id");
        $st->execute([':id'=>$uid]);
        if($row=$st->fetch(PDO::FETCH_ASSOC)){
          if(!empty($row['roles'])) $dbRoles=array_merge($dbRoles,array_map('trim',explode(',',(string)$row['roles'])));
          if(!empty($row['role'])) $dbRoles[]=$row['role'];
          if(!empty($row['is_admin'])) $dbRoles[]='Admin';
          if(!empty($row['is_comercial'])) $dbRoles[]='Comercial';
        }
      }catch(Throwable $e){}
      if(!$dbRoles){
        try{
          $st=pdo()->prepare("SELECT r.name AS role_name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=:id");
          $st->execute([':id'=>$uid]);
          while($r=$st->fetch(PDO::FETCH_ASSOC)) if(!empty($r['role_name'])) $dbRoles[]=$r['role_name'];
        }catch(Throwable $e){}
      }
      if(!$dbRoles){
        foreach(['role_name','role'] as $col){
          try{
            $st=pdo()->prepare("SELECT {$col} FROM user_roles WHERE user_id=:id");
            $st->execute([':id'=>$uid]);
            while($r=$st->fetch(PDO::FETCH_ASSOC)) if(!empty($r[$col])) $dbRoles[]=$r[$col];
            if($dbRoles) break;
          }catch(Throwable $e){}
        }
      }
    }
    $all=normalize_roles(array_merge($sessRoles,$dbRoles));
    $_SESSION['uroles']=$all;
    return $all;
  }
}
if (!function_exists('user_has_role')) {
  function user_has_role(string $role): bool {
    $wanted = mb_strtolower(normalize_role_name($role),'UTF-8');
    foreach(current_user_roles() as $r) if(mb_strtolower($r,'UTF-8')===$wanted) return true;
    return false;
  }
}
if (!function_exists('session_has_role_slug')) {
  function session_has_role_slug(string $wanted): bool {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    $wanted = mb_strtolower(trim($wanted),'UTF-8');
    $roles=[];
    if(!empty($_SESSION['user']['roles']) && is_array($_SESSION['user']['roles'])){
      $roles=array_map(fn($r)=>mb_strtolower((string)$r,'UTF-8'),$_SESSION['user']['roles']);
    }
    foreach(['role','perfil','cargo'] as $k){
      if(!empty($_SESSION['user'][$k]) && !is_array($_SESSION['user'][$k])){
        foreach(preg_split('/[;,|,]/',(string)$_SESSION['user'][$k])?:[] as $p){ $roles[]=mb_strtolower(trim($p),'UTF-8'); }
      }
    }
    if(!empty($_SESSION['user']['is_admin'])) $roles[]='admin';
    $norm = static function($txt){ $txt=iconv('UTF-8','ASCII//TRANSLIT//IGNORE',$txt); $txt=strtolower($txt); return preg_replace('/\s+/', '', $txt); };
    $wantedN = $norm($wanted);
    foreach($roles as $r) if($norm($r)===$wantedN) return true;
    return false;
  }
}

/* ---------------------- Auto-detector de ativo ---------------------- */
if (!function_exists('boden_detect_active')) {
  function boden_detect_active(): string {
    $path = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    if ($path === '') $path = (string)($_SERVER['PHP_SELF'] ?? '');
    if ($path === '') $path = (string)(parse_url((string)($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) ?? '');
    $base = strtolower(basename($path));
    if ($base === '' || $base === 'boden') $base = 'index.php';
    $map = [
      'index.php'            => 'form',
      'safra_dashboard.php'  => 'dashboard',
      'safra_variedade.php'  => 'variedade',
      'users_admin.php'      => 'users',
    ];
    return $map[$base] ?? '';
  }
}

/* --------------------------- Renderer --------------------------- */
if (!function_exists('render_boden_navbar')) {
  /**
   * @param string $active  'form'|'dashboard'|'variedade'|'users' (opcional)
   * @param array  $opts     ['basePath'=>'/boden']
   */
  function render_boden_navbar(string $active = '', array $opts = []): void {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();

    $active = $active !== '' ? strtolower($active) : boden_detect_active();
    $base   = rtrim($opts['basePath'] ?? '/boden','/');
    $sessionResp  = current_user_display_name();
    $sessionEmail = current_user_email();

    // Permissões:
    $isComercial = (user_can_safe('view','page_dashboard_var') ?? false)
                || (user_can_safe('access','comercial_area') ?? false)
                || user_has_role('Comercial') || session_has_role_slug('comercial');
    $isAdmin     = (user_can_safe('manage','admin_users') ?? false)
                || (user_can_safe('admin','system') ?? false)
                || user_has_role('Admin') || session_has_role_slug('admin');

    $canDashVar  = $isComercial || $isAdmin || can_view_dashboard_var_safe();
    $canUsers    = $isAdmin || can_manage_users_safe();

    $isAct = fn(string $k)=> $active === $k;

    static $fontOnce=false,$styleOnce=false;
    if(!$fontOnce){ $fontOnce=true;
      echo '<link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@400;600;700&display=swap" rel="stylesheet">';
    }
    if(!$styleOnce){ $styleOnce=true; ?>
      <style>
        :root{ --pill-bg:#b9dd2c; --pill-on:#98c61f; --pill-text:#2a2a2a; --pill-hover:#8fbe1a; --brand:#5fb141; --glass:#ffffffcc; --line:rgba(0,0,0,.06); }
        .prod-nav, .prod-nav *{ font-family:"Josefin Sans",system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; }
        .prod-nav{ position:sticky; top:0; z-index:1030; background:var(--glass); backdrop-filter:saturate(1.2) blur(4px); border-bottom:1px solid var(--line); }
        .prod-container{ max-width:1120px; margin:0 auto; padding:0 16px; }
        .prod-flex{ display:flex; align-items:center; gap:12px; }
        .prod-brand-badge{ width:150px;height:63px;display:inline-flex;align-items:center;justify-content:center;}
        .prod-brand-badge img{ width:140px;height:53px;display:block; }
        .prod-brand-title{ font-weight:700;font-size:1.25rem;color:#111;text-decoration:none }
        .prod-pill-wrap{ background:var(--pill-bg); border-radius:999px; box-shadow:0 6px 16px rgba(0,0,0,.08); padding:.25rem; gap:.125rem; }
        .prod-pill a, .prod-pill button{ color:var(--pill-text); font-weight:700; border-radius:999px; padding:.6rem 1.25rem; letter-spacing:.02em; text-decoration:none; border:0; background:transparent; cursor:pointer; }
        .prod-pill a:hover, .prod-pill button:hover, .prod-pill a:focus, .prod-pill button:focus{ background:var(--pill-hover); color:#fff; outline:none; }
        .prod-pill .active{ background:var(--pill-on); color:#fff; text-shadow:0 1px 0 rgba(0,0,0,.08); }
        .icon-circle{ width:40px;height:40px;border-radius:50%; background:#b9dd2c;color:#fff; display:inline-flex;align-items:center;justify-content:center; text-decoration:none; box-shadow:0 2px 8px rgba(0,0,0,.08); font-weight:700; }
        .icon-circle--sm{ width:32px;height:32px; }
        .prod-dropdown{ position:relative; }
        .prod-dropdown-menu{ position:absolute; top:100%; left:0; min-width:220px; background:#e6f3bf; border:0; border-radius:16px; padding:.5rem; box-shadow:0 10px 24px rgba(0,0,0,.12); margin-top:.5rem; display:none; }
        .prod-dropdown.open .prod-dropdown-menu{ display:block; }
        .prod-dropdown-menu a{ display:block; border-radius:999px; font-weight:700; color:#2a2a2a; padding:.55rem 1rem; text-decoration:none; }
        .prod-dropdown-menu a:hover{ background:#b9dd2c; color:#111; }
        .prod-dropdown-toggle::after{ content:""; display:inline-block; margin-left:.5rem; border:5px solid transparent; border-top-color:#1e1e1e; vertical-align:middle; }
        .offcanvas{ position:fixed; left:0; top:0; bottom:0; width:300px; max-width:85vw; transform:translateX(-100%); background:#ecf7c8; transition:transform .2s ease; z-index:1040; }
        .offcanvas.open{ transform:none; }
        .offcanvas-header{ display:flex; align-items:center; justify-content:space-between; padding:14px 14px 8px; }
        .offcanvas-body{ display:flex; flex-direction:column; gap:12px; padding:8px 14px 16px; height:calc(100% - 52px); }
        .menu-group{ padding:12px 0; } .menu-group + .menu-group{ border-top:1px dashed rgba(0,0,0,.12); }
        .section-title{ display:flex; align-items:center; gap:8px; font-weight:900; text-transform:uppercase; font-size:.78rem; color:#fff; padding:6px 10px; border-radius:999px; background:linear-gradient(180deg,#5fb141 0%, #5fb141 100%); box-shadow:inset 0 -1px 0 rgba(255,255,255,.6), 0 4px 10px rgba(0,0,0,.06); }
        .section-body a{ display:block; padding:.6rem .75rem; border-radius:24px; color:#2a2a2a; font-weight:700; text-decoration:none; }
        .section-body a.active{ background:#b9dd2c; color:#0f2a08; box-shadow:0 2px 8px rgba(0,0,0,.08); }
        .user-card{ position:relative; background:#ecf7c8; border-radius:16px; padding:12px; min-width:260px; box-shadow:0 10px 24px rgba(0,0,0,.12); display:none; }
        .user-card.open{ display:block; position:absolute; right:0; top:100%; margin-top:8px; }
        .user-card .avatar{ width:40px;height:40px;border-radius:50%; background:#b9dd2c; display:inline-flex; align-items:center; justify-content:center; }
        .user-card .email{ font-size:.95rem; color:#2b3a28; font-weight:700; }
        .prod-mobile-only{ display:none; }
        @media (max-width: 767.98px){
          .prod-center{ display:none !important; }
          .prod-mobile-only{ display:flex; align-items:center; gap:.5rem; }
          .prod-brand-badge{ width:122px;height:52px; } .prod-brand-badge img{ width:112px;height:42px; }
          .prod-flex{ display:flex; align-items:center; gap:12px; justify-content: space-between; }
        }
        .btn-close{ border:0; background:transparent; width:32px; height:32px; border-radius:50%; cursor:pointer; }
        .btn-close:before{ content:"×"; font-size:22px; line-height:32px; display:block; text-align:center; }
        .prod-link{ color:inherit; text-decoration:none; }
      </style>
    <?php }

    // URLs e flags
    $urlForm   = h('/index.php');
    $urlDash   = h('/safra_dashboard.php');
    $urlVar    = h('/safra_variedade.php');
    $urlUsers  = h('/users_admin.php');
    $urlLogout = h('/logout.php');
    $logoSrc   = h('/boden.png');

    $isForm  = $isAct('form');
    $isDash  = $isAct('dashboard');
    $isVar   = $isAct('variedade');
    $isUsers = $isAct('users');
    $dashAnyActive = $isDash || $isVar;
    ?>
    <nav class="prod-nav" data-active="<?php echo h($active); ?>" data-base="<?php echo h($base); ?>">
      <div class="prod-container">
        <div class="prod-flex" style="height:64px;">
          <!-- ESQUERDA -->
          <div class="prod-flex" style="gap:8px;">
            <button class="icon-circle prod-mobile-only" id="bnv-burger" aria-label="Abrir menu" title="Menu" type="button">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M4 6h16M4 12h16M4 18h16" stroke="#1e1e1e" stroke-width="2" stroke-linecap="round"/>
              </svg>
            </button>
            <a href="<?php echo $urlForm; ?>" class="prod-link" style="display:flex;align-items:center;gap:10px;">
              <div class="prod-brand-badge"><img src="<?php echo $logoSrc; ?>" alt="Boden"></div>
            </a>
          </div>

          <!-- CENTRO -->
          <div class="prod-center" style="flex:1; display:flex; justify-content:center;">
            <div class="prod-pill-wrap" style="display:inline-flex;">
              <div class="prod-pill" style="display:flex; align-items:center; gap:2px;">
                <a id="lnk-form" href="<?php echo $urlForm; ?>" class="<?php echo $isForm ? 'active' : ''; ?>">Formulário</a>

                <div class="prod-dropdown" id="bnv-dd-dash">
                  <button id="btn-dash" type="button" class="prod-dropdown-toggle <?php echo $dashAnyActive ? 'active' : ''; ?>" aria-haspopup="true" aria-expanded="<?php echo $dashAnyActive ? 'true':'false'; ?>">
                    Dashboards
                  </button>
                  <div class="prod-dropdown-menu" role="menu">
                    <a id="lnk-dash" href="<?php echo $urlDash; ?>" class="<?php echo $isDash ? 'active' : ''; ?>">Geral</a>
                    <?php if ($canDashVar): ?>
                      <a id="lnk-var" href="<?php echo $urlVar; ?>" class="<?php echo $isVar ? 'active' : ''; ?>">Variedade</a>
                    <?php endif; ?>
                  </div>
                </div>

                <?php if ($canUsers): ?>
                  <a id="lnk-users" href="<?php echo $urlUsers; ?>" class="<?php echo $isUsers ? 'active' : ''; ?>">Usuários</a>
                <?php endif; ?>
              </div>
            </div>
          </div>

          <!-- DIREITA -->
          <div class="prod-flex" style="gap:.5rem;">
            <div class="prod-mobile-only">
              <a href="javascript:history.back()" class="icon-circle icon-circle--sm" title="Voltar" aria-label="Voltar">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M15 18l-6-6 6-6" stroke="#1e1e1e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </a>
            </div>

            <div class="prod-desktop-user" style="display:flex; align-items:center; gap:.5rem;">
              <span class="prod-desktop-greet" style="display:none; font-size:.95rem; color:#1b1b1b;">
                Olá, <strong><?php echo h($sessionResp ?: 'Usuário'); ?></strong>
              </span>
              <div class="prod-dropdown" id="bnv-dd-user" style="position:relative;">
                <a href="#" class="icon-circle" aria-haspopup="true" aria-expanded="false" title="Usuário" id="bnv-user-btn">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="12" cy="8" r="3.2" stroke="#1e1e1e" stroke-width="2"/>
                    <path d="M5 19a7 7 0 0 1 14 0" stroke="#1e1e1e" stroke-width="2" fill="none"/>
                  </svg>
                </a>
                <div class="user-card" id="bnv-user-card" role="menu" aria-label="Menu do usuário">
                  <div class="prod-flex" style="gap:8px; align-items:center; margin-bottom:8px;">
                    <div class="avatar">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                        <circle cx="12" cy="8" r="3.2" stroke="#1e1e1e" stroke-width="2"/>
                        <path d="M5 19a 7 7 0 0 1 14 0" stroke="#1e1e1e" stroke-width="2" fill="none"/>
                      </svg>
                    </div>
                    <div class="email"><?php echo h($sessionEmail ?: ''); ?></div>
                  </div>
                  <form method="POST" action="<?php echo $urlLogout; ?>" class="m-0">
                    <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
                    <button type="submit" style="width:100%; padding:.6rem .9rem; border-radius:12px; border:0; background:#e65a5a; color:#fff; font-weight:700; cursor:pointer;">Sair</button>
                  </form>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    </nav>

    <!-- OFFCANVAS -->
    <div class="offcanvas" id="bnv-offcanvas" aria-hidden="true" aria-labelledby="bnv-offcanvas-title">
      <div class="offcanvas-header">
        <h5 id="bnv-offcanvas-title" style="font-weight:800; margin:0;">Menu</h5>
        <button type="button" class="btn-close" id="bnv-offcanvas-close" aria-label="Fechar"></button>
      </div>
      <div class="offcanvas-body">
        <div class="menu-group">
          <div class="section-title">Formulário</div>
          <div class="section-body">
            <a href="<?php echo $urlForm; ?>" id="m-lnk-form">Formulário</a>
          </div>
        </div>

        <div class="menu-group">
          <div class="section-title">Dashboards</div>
          <div class="section-body">
            <a href="<?php echo $urlDash; ?>" id="m-lnk-dash">Geral</a>
            <?php if ($canDashVar): ?>
              <a href="<?php echo $urlVar; ?>" id="m-lnk-var">Variedade</a>
            <?php endif; ?>
          </div>
        </div>

        <?php if ($canUsers): ?>
          <div class="menu-group">
            <div class="section-title">Admin</div>
            <div class="section-body">
              <a href="<?php echo $urlUsers; ?>" id="m-lnk-users">Usuários</a>
            </div>
          </div>
        <?php endif; ?>

        <form method="POST" action="<?php echo $urlLogout; ?>" class="mt-auto">
          <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
          <button type="submit" style="width:100%; padding:.7rem 1rem; border-radius:12px; border:0; background:#e65a5a; color:#fff; font-weight:800; cursor:pointer;">Sair</button>
        </form>
      </div>
    </div>

    <script>
      (function(){
        const $ = (sel,ctx=document)=>ctx.querySelector(sel);
        const $$= (sel,ctx=document)=>Array.from(ctx.querySelectorAll(sel));

        // ===== Offcanvas =====
        const off = $('#bnv-offcanvas');
        $('#bnv-burger')?.addEventListener('click', ()=>{ off.classList.add('open'); off.setAttribute('aria-hidden','false'); document.body.style.overflow='hidden'; });
        $('#bnv-offcanvas-close')?.addEventListener('click', ()=>{ off.classList.remove('open'); off.setAttribute('aria-hidden','true'); document.body.style.overflow=''; });
        document.addEventListener('keydown', (e)=>{ if(e.key==='Escape') { off.classList.remove('open'); off.setAttribute('aria-hidden','true'); document.body.style.overflow=''; } });

        // ===== Dropdown genérico (Dashboards) =====
        function wireDropdown(rootSel, toggleSel='.prod-dropdown-toggle', menuSel='.prod-dropdown-menu'){
          const root = $(rootSel); if(!root) return;
          const toggle = $(toggleSel, root);
          const close= ()=>{ root.classList.remove('open'); toggle?.setAttribute('aria-expanded','false'); };
          toggle?.addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); const on = root.classList.toggle('open'); toggle?.setAttribute('aria-expanded', on?'true':'false'); });
          document.addEventListener('click', (e)=>{ if(!root.contains(e.target)) close(); });
          $$('.prod-dropdown-menu a', root).forEach(a=> a.addEventListener('click', close));
        }
        wireDropdown('#bnv-dd-dash');

        // ===== User menu =====
        const userRoot = $('#bnv-dd-user');
        const userBtn  = $('#bnv-user-btn');
        const userCard = $('#bnv-user-card');
        const userClose= ()=>{ userCard?.classList.remove('open'); userBtn?.setAttribute('aria-expanded','false'); };
        userBtn?.addEventListener('click', (e)=>{ e.preventDefault(); e.stopPropagation(); const was=userCard.classList.contains('open'); if(was){ userClose(); } else { userCard?.classList.add('open'); userBtn?.setAttribute('aria-expanded','true'); }});
        document.addEventListener('click', (e)=>{ if(userRoot && !userRoot.contains(e.target)) userClose(); });

        // ===== Ativo (fallback no front-end) =====
        function basename(p){ try{ p = p.split('?')[0].split('#')[0]; }catch{}; const i = p.lastIndexOf('/'); return i>=0 ? p.slice(i+1) : p; }
        const nav = document.querySelector('.prod-nav');
        const declared = (nav?.dataset.active||'').toLowerCase();
        let active = declared;

        if(!active){
          const file = basename(location.pathname || '');
          if (file === '' || file === 'boden' || file === 'boden/') active = 'form';
          else if (file === 'index.php') active = 'form';
          else if (file === 'safra_dashboard.php') active = 'dashboard';
          else if (file === 'safra_variedade.php') active = 'variedade';
          else if (file === 'users_admin.php') active = 'users';
        }

        // Limpa qualquer active server-side e aplica o correto
        function setActive(a){
          ['#lnk-form','#lnk-dash','#lnk-var','#lnk-users','#m-lnk-form','#m-lnk-dash','#m-lnk-var','#m-lnk-users'].forEach(id=>{
            const el = document.querySelector(id);
            if (el) el.classList.remove('active');
          });
          const map = {
            'form': ['#lnk-form','#m-lnk-form'],
            'dashboard': ['#lnk-dash','#m-lnk-dash'],
            'variedade': ['#lnk-var','#m-lnk-var'],
            'users': ['#lnk-users','#m-lnk-users'],
          };
          (map[a]||[]).forEach(id=>{ const el=document.querySelector(id); if(el) el.classList.add('active'); });
          // Acende o botão "Dashboards" quando for dashboard/variedade
          const btnDash = document.querySelector('#btn-dash');
          if (btnDash) {
            if (a==='dashboard' || a==='variedade') btnDash.classList.add('active');
            else btnDash.classList.remove('active');
          }
        }
        setActive(active);

        // Saudação opcional no desktop
        const greet = document.querySelector('.prod-desktop-greet');
        if (greet) { try{ if (window.matchMedia('(min-width: 992px)').matches) greet.style.display='inline'; }catch(_){} }
      })();
    </script>
    <?php
  }
}
