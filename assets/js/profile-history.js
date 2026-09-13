(() => {
  if (window.openUEMProfileHistoryInstalled) return;
  window.openUEMProfileHistoryInstalled = true;
  const focusHistory = () => document.getElementById('profile-history-heading')?.focus({ preventScroll: true });
  document.addEventListener('htmx:afterSettle', (event) => {
    if (event.detail.target?.id === 'main') focusHistory();
  });
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', focusHistory, { once: true });
  } else {
    focusHistory();
  }
})();
