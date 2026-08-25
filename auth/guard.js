(() => {
  'use strict';
  document.documentElement.style.visibility = 'hidden';
  async function boot() {
    try {
      const user = await window.NDDAuth.requireAuth();
      if (!user) return;
      document.documentElement.style.visibility = '';
      window.dispatchEvent(new CustomEvent('ndd:authenticated', { detail: user }));
    } catch (_) {
      location.replace((window.NDD_PORTAL_CONFIG || {}).loginPage || '/Extrato_de_Horas/login.html');
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, { once:true });
  else boot();
})();
