(() => {
  'use strict';
  if (window.openUEMWiFiEAP) { window.openUEMWiFiEAP(); return; }
  function initialize() {
    document.querySelectorAll('.wifi-eap-profile-editor').forEach(form => {
      if (form.dataset.initialized) return;
      form.dataset.initialized = 'true';
      const field = name => form.elements.namedItem(name);
      function update() {
        let cleared = false;
        ['identity_revision', 'trust_revision'].forEach(name => {
          const select = field(name);
          Array.from(select.options).forEach(option => {
            if (!option.dataset.scope) return;
            option.disabled = option.dataset.scope !== field('payload_scope').value;
            option.hidden = option.disabled;
          });
          if (select.selectedOptions[0]?.dataset.scope && select.selectedOptions[0].disabled) {
            select.value = '';
            cleared = true;
          }
        });
        if (cleared) {
          field('confirmed').checked = false;
          form.querySelector('[data-certificate-selection-status]').textContent = 'Certificate selections were cleared because their scope does not match. Select matching revisions or explicitly choose existing device trust, then review again.';
        }
        const minimum = field('tls_minimum').value;
        field('tls_maximum').setCustomValidity(minimum > field('tls_maximum').value ? 'The TLS maximum must be at least the minimum.' : '');
        field('outer_identity').required = minimum === '1.3';
        const bytes = new TextEncoder().encode(field('ssid').value).length;
        field('ssid').setCustomValidity(bytes > 32 ? 'The network name exceeds 32 UTF-8 bytes.' : '');
      }
      form.addEventListener('change', update);
      form.addEventListener('input', update);
      form.addEventListener('reset', () => queueMicrotask(update));
      update();
    });
  }
  window.openUEMWiFiEAP = initialize;
  initialize();
  document.addEventListener('htmx:afterSwap', initialize);
})();
