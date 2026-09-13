(() => {
  if (window.openUEMManualExecutionInstalled) return;
  window.openUEMManualExecutionInstalled = true;
  const focus = () => document.getElementById('manual-execution-heading')?.focus({ preventScroll: true });
  document.addEventListener('htmx:afterSettle', event => {
    if (event.detail.target?.id === 'main') focus();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', focus, { once: true });
  else focus();
})();
