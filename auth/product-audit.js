(() => {
  'use strict';
  const safe = fn => Promise.resolve().then(fn).catch(err => console.warn('Auditoria NDD indisponivel:', err?.message || err));
  function value(id) { const el=document.getElementById(id); return el ? ('value' in el ? el.value : el.textContent) : null; }
  function checked(id) { const el=document.getElementById(id); return el ? Boolean(el.checked) : null; }
  function common(product) {
    return {
      product,
      clientName: value('cliente') || value('spanCliente1') || value('spanCliente2'),
      clientDocument: value('cnpjs'),
      payload: {
        cliente: value('cliente'), data: value('data'), cnpjs: value('cnpjs'), usuarios: value('usuarios'),
        integracao: checked('modIntegracao'), appConector: checked('modApp'), pathname: location.pathname
      }
    };
  }
  function install({product, calculateButtonId='calcularBtn', printButtonId='imprimirBtn', snapshot}) {
    const calc=document.getElementById(calculateButtonId), print=document.getElementById(printButtonId);
    if (calc) calc.addEventListener('click', () => setTimeout(() => safe(() => window.NDDAuth.audit('CALCULO_EXTRATO', { ...common(product), result: snapshot ? snapshot() : null })), 0));
    if (print) print.addEventListener('click', () => safe(async () => {
      const info=common(product), snap=snapshot ? snapshot() : info.payload;
      const action=await window.NDDAuth.audit('GEROU_EXTRATO', { ...info, result:snap });
      await window.NDDAuth.saveDocument('EXTRATO', product, snap, { actionLogId:action.id, clientName:info.clientName });
    }), true);
    safe(() => window.NDDAuth.audit('ABRIU_PRODUTO', { product, pagePath:location.pathname }));
  }
  window.NDDProductAudit=Object.freeze({install});
})();
