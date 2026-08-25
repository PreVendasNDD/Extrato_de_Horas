(async () => {
  if (NDDAuth.token()) {
    try {
      await NDDAuth.requireAuth();
      if (NDDAuth.token()) location.replace(NDD_PORTAL_CONFIG.portalPage);
    } catch (_) {}
  }
})();

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const btn = document.getElementById('submit');
  const err = document.getElementById('error');

  err.textContent = '';
  btn.disabled = true;
  btn.textContent = 'Entrando...';

  try {
    await NDDAuth.login(
      document.getElementById('username').value.trim(),
      document.getElementById('password').value
    );
    location.replace(NDD_PORTAL_CONFIG.portalPage);
  } catch (ex) {
    err.textContent = ex.status === 401
      ? 'Usuário ou senha inválidos.'
      : 'Não foi possível acessar o servidor.';
    btn.disabled = false;
    btn.textContent = 'Entrar';
  }
});
