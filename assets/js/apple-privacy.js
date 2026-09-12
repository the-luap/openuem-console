(() => {
  "use strict";
  if (window.openUEMPrivacy) { window.openUEMPrivacy(); return; }
  function initialize() {
    document.querySelectorAll(".privacy-editor:not([data-initialized])").forEach(form => {
      form.dataset.initialized = "yes";
      const service = form.elements.service, policy = form.elements.policy;
      const receiver = form.querySelector("[data-privacy-receiver]");
      const compatibility = form.querySelector("[data-privacy-compatibility]");
      const status = form.querySelector("[data-privacy-policy-status]");
      function update() {
        const selected = service.selectedOptions[0];
        const allow = policy.querySelector('[value="allow"]');
        const standard = policy.querySelector('[value="user"]');
        allow.disabled = !service.value || selected.dataset.denyOnly === "true";
        standard.disabled = !service.value || selected.dataset.standardUser !== "true";
        if (policy.selectedOptions[0].disabled) {
          policy.value = "deny";
          status.textContent = "Policy changed to Deny because the previous choice is unavailable for this service. Review the new policy before saving.";
        } else { status.textContent = ""; }
        receiver.hidden = receiver.disabled = service.value !== "AppleEvents";
        let minimum = selected.dataset.minimum;
        if (policy.value === "user") minimum = "11.0";
        compatibility.textContent = service.value ? `Requires macOS ${minimum} or later.` : "Select a privacy service to see its macOS requirements.";
        if (service.value === "Accessibility" && policy.value === "allow") compatibility.textContent += " Profile-based Accessibility grants are deprecated on macOS 26.2 and unavailable on macOS 27 or later.";
      }
      service.addEventListener("change", update);
      policy.addEventListener("change", update);
      form.addEventListener("reset", () => queueMicrotask(update));
      update();
    });
  }
  window.openUEMPrivacy = initialize;
  document.addEventListener("DOMContentLoaded", initialize);
  document.addEventListener("htmx:afterSwap", initialize);
  initialize();
})();
