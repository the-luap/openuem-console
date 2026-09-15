(() => {
  "use strict";
  if (window.openUEMSystemExtensions) { window.openUEMSystemExtensions(); return; }
  function initialize() {
    document.querySelectorAll(".system-extensions-editor:not([data-initialized])").forEach(form => {
      form.dataset.initialized = "yes";
      const mode = form.elements.approval_mode;
      const approvals = form.querySelector("[data-extension-approvals]");
      const bundles = form.querySelector("[data-extension-bundles]");
      function update() {
        approvals.hidden = approvals.disabled = mode.value === "block";
        bundles.hidden = bundles.disabled = mode.value !== "listed";
      }
      mode.addEventListener("change", update);
      form.addEventListener("reset", () => queueMicrotask(update));
      update();
    });
  }
  window.openUEMSystemExtensions = initialize;
  document.addEventListener("DOMContentLoaded", initialize);
  document.addEventListener("htmx:afterSwap", initialize);
  initialize();
})();
