(() => {
  if (window.openUEMProfileEditorInstalled) return;
  window.openUEMProfileEditorInstalled = true;
  let tagFocus = 'profile-tag-heading';
  document.addEventListener('htmx:beforeRequest', (event) => {
    if (event.detail.target?.id === 'profile-tag-panel') {
      tagFocus = event.detail.elt?.id === 'profile-tag-search' ? 'profile-tag-query' : 'profile-tag-heading';
    }
    if (event.detail.elt?.id !== 'profile-tag-search') return;
    const choice = document.getElementById('profile-tag-choice');
    if (choice) choice.value = '';
  });
  document.addEventListener('htmx:afterSwap', (event) => {
    if (event.detail.target?.id !== 'profile-tag-panel') return;
    document.getElementById(tagFocus)?.focus({ preventScroll: true });
    tagFocus = 'profile-tag-heading';
  });
})();
