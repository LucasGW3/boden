(function(){
  // Guard: só roda uma vez
  if (window.__W3_flatpickr_initialized) return;
  window.__W3_flatpickr_initialized = true;

  // Localiza PT (se disponível) e define como padrão
  if (window.flatpickr && window.flatpickr.l10ns && window.flatpickr.l10ns.pt) {
    flatpickr.localize(flatpickr.l10ns.pt);
  }

  const DEFAULTS = {
    dateFormat: "Y-m-d",     // valor real do input (para PHP)
    altInput: true,          // mostra input "bonito"
    altFormat: "d/m/Y",      // formato exibido
    altInputClass: "fp-alt", // classe do input alternativo
    locale: "pt",
    disableMobile: true,
    allowInput: true
  };

  const seen = new WeakSet();
  function attach(el){
    if (!el || seen.has(el)) return;
    if (el._flatpickr) { try { el._flatpickr.destroy(); } catch(_){} }
    flatpickr(el, DEFAULTS);
    seen.add(el);
  }

  function initAll(){
    document.querySelectorAll('input[type="date"], input[data-role="date"]').forEach(attach);
  }

  // Ativa nos inputs atuais
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAll);
  } else {
    initAll();
  }

  // Observa novos inputs adicionados dinamicamente (ex.: modais)
  const mo = new MutationObserver((muts)=>{
    for (const m of muts){
      m.addedNodes.forEach(node=>{
        if (!(node instanceof HTMLElement)) return;
        if (node.matches?.('input[type="date"], input[data-role="date"]')) attach(node);
        node.querySelectorAll?.('input[type="date"], input[data-role="date"]').forEach(attach);
      });
    }
  });
  mo.observe(document.documentElement, { childList:true, subtree:true });
})();
