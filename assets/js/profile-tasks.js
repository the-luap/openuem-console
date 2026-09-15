(() => {
  if (window.openUEMProfileTasksInitialized) return;
  window.openUEMProfileTasksInitialized = true;
  const focus = new Map();
  const regionFor = id => Array.from(document.querySelectorAll('[data-profile-tasks]')).find(region => region.dataset.profileId === id);
  document.addEventListener('profileTaskOrderSaved', event => {
    const detail = event.detail || {};
    const region = regionFor(String(detail.profileId));
    if (!region || !Number.isSafeInteger(detail.page) || detail.page < 1 || detail.page > 1000000 || !/^[1-9][0-9]*$/.test(String(detail.taskId))) {
      event.stopPropagation();
      return;
    }
    region.querySelector('input[name="page"]').value = String(detail.page);
    focus.set(region.dataset.profileId, String(detail.taskId));
  }, true);
  document.addEventListener('htmx:responseError', event => {
    const source = event.detail?.elt;
    const action = source instanceof Element && source.matches('[data-task-order-action]') ? source : null;
    const region = action?.closest('[data-profile-tasks]');
    if (!region) return;
    if (action.dataset.taskId) focus.set(region.dataset.profileId, action.dataset.taskId);
    // A failed optimistic drag restores the current server order. The list GET
    // has no action marker, so its own errors cannot create a refresh loop.
    window.htmx.trigger(document.body, 'profileTaskListRefresh');
  });
  document.addEventListener('htmx:afterSwap', event => {
    const target = event.detail?.target || event.target;
    const prior = target instanceof Element && target.matches('[data-profile-tasks]') ? target : null;
    if (!prior) return;
    const region = regionFor(prior.dataset.profileId);
    const task = focus.get(prior.dataset.profileId);
    if (!region || !task) return;
    focus.delete(prior.dataset.profileId);
    const link = Array.from(region.querySelectorAll('a[id]')).find(link => link.id === 'task-name-' + task);
    (link || region).focus({ preventScroll: true });
    link?.scrollIntoView({ block: 'nearest' });
  });
})();
