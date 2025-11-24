<?php
// ui/datepicker.php
// Wrapper para injetar Flatpickr globalmente (tema + init)

if (!function_exists('render_datepicker_assets')) {
  function render_datepicker_assets() {
    // Evita injetar duplicado se já foi chamado antes
    static $loaded = false;
    if ($loaded) return; $loaded = true;

    $base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/'); // caminho base do script atual
    $themeCss = $base . '/assets/datepicker/flatpickr-theme.css';
    $initJs   = $base . '/assets/datepicker/flatpickr-init.js';

    echo <<<HTML
<!-- Flatpickr (base CSS) -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<!-- Tema custom -->
<link rel="stylesheet" href="{$themeCss}">
<!-- Flatpickr (scripts) -->
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/pt.js"></script>
<!-- Inicialização global -->
<script defer src="{$initJs}"></script>
HTML;
  }
}
