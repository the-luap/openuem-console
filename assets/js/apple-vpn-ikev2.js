(() => {
  'use strict';
  if (window.openUEMIKEv2) { window.openUEMIKEv2(); return; }
  function initialize() {
    document.querySelectorAll('.ikev2-certificate-editor').forEach(form => {
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
        const kind = field('identity_revision').selectedOptions[0]?.dataset.identityKind;
        const rsaOnly = kind === 'com.apple.security.scep' || kind === 'com.apple.ADCertificate.managed';
        const algorithm = field('certificate_type');
        Array.from(algorithm.options).forEach(option => {
          option.disabled = rsaOnly && option.value.startsWith('ECDSA');
          option.hidden = option.disabled;
        });
        if (algorithm.selectedOptions[0]?.disabled) {
          algorithm.value = '';
          cleared = true;
        }
        if (cleared) {
          field('confirmed').checked = false;
          form.querySelector('[data-ikev2-selection-status]').textContent = 'Incompatible certificate selections were cleared. Select matching revisions, trust and algorithm, then review again.';
        }
        form.querySelector('[data-ikev2-version-status]').textContent = field('authentication_mode').value === 'eap-tls'
          ? 'EAP-TLS uses TLS 1.2 and requires macOS 10.13 or iOS/iPadOS 11 or later. Certificate options can require newer versions.'
          : 'Machine certificate profiles require macOS 10.11 or iOS/iPadOS 8 or later. Certificate options can require newer versions.';
      }
      form.addEventListener('change', update);
      form.addEventListener('reset', () => queueMicrotask(update));
      update();
    });
  }
  window.openUEMIKEv2 = initialize;
  initialize();
  document.addEventListener('htmx:afterSwap', initialize);
})();
