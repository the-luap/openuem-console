(() => {
  if (window.openUEMNetbirdFocus) return;
  window.openUEMNetbirdFocus = true;
  document.addEventListener("htmx:afterSwap", (event) => {
    if (event.detail.target?.id !== "main") return;
    document.querySelector("#netbird-operation-heading")?.focus();
  });
})();
