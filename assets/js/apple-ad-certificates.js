(() => {
  'use strict';
  if (window.openUEMADCertificates) { window.openUEMADCertificates(); return; }
  function initialize() {
    document.querySelectorAll('.ad-certificate-editor').forEach(form => {
      if (form.dataset.initialized) return;
      form.dataset.initialized = 'true';
      const field = name => form.elements.namedItem(name);
      function update() {
        const renewal = field('auto_renewal');
        const enabled = Array.from(renewal.options).find(option => option.value === 'true');
        const user = field('payload_scope').value === 'User';
        if (user && renewal.value === 'true') {
          renewal.value = '';
          field('confirmed').checked = false;
          form.querySelector('[data-ad-scope-status]').textContent = 'Automatic renewal was cleared because it requires a computer certificate. Review the user certificate settings again.';
        }
        enabled.disabled = user;
        enabled.hidden = user;
      }
      form.addEventListener('change', update);
      form.addEventListener('reset', () => queueMicrotask(update));
      update();
    });
  }
  window.openUEMADCertificates = initialize;
  initialize();
  document.addEventListener('htmx:afterSwap', initialize);
})();
