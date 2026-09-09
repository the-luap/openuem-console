(() => {
  "use strict";
  if (window.openUEMADEPlatformSSO) { window.openUEMADEPlatformSSO(); return; }
  function initialize() {
    document.querySelectorAll(".ade-sso-options:not([data-initialized])").forEach(container => {
      container.dataset.initialized = "yes";
      const enable = container.querySelector("[data-sso-enable]");
      const fields = container.querySelector("[data-sso-fields]");
      if (enable && fields) {
        function toggle() { fields.hidden = fields.disabled = !enable.checked; }
        enable.addEventListener("change", toggle);
        toggle();
      }
      const root = container.querySelector(".ade-sso-picker");
      const input = root.querySelector("[data-sso-search]");
      const status = root.querySelector("[data-sso-status]");
      const results = root.querySelector("[data-sso-results]");
      const selectedList = root.querySelector("[data-sso-selected]");
      const nextButton = root.querySelector("[data-sso-next]");
      let options = [], selected, next = "", query = "", request, removeButton;
      function button(label, action) {
        const element = document.createElement("button");
        element.type = "button";
        element.className = "uk-button uk-button-default";
        element.textContent = label;
        element.addEventListener("click", action);
        return element;
      }
      function row(label) {
        const li = document.createElement("li"), span = document.createElement("span");
        span.textContent = label;
        li.append(span);
        return li;
      }
      function render() {
        selectedList.replaceChildren();
        if (selected) {
          const li = row(selected.label), hidden = document.createElement("input");
          hidden.type = "hidden"; hidden.name = root.dataset.input || "sso_profile_revision"; hidden.value = selected.id;
          removeButton = button("Remove selection", () => { selected = undefined; render(); input.focus(); status.textContent = "Profile selection removed."; });
          removeButton.setAttribute("aria-label", `Remove ${selected.label}`);
          li.append(hidden, removeButton); selectedList.append(li);
        } else selectedList.append(row("No profile selected."));
        input.setCustomValidity(selected ? "" : "Select a profile prepared for unattended ADE.");
        results.replaceChildren();
        options.forEach(item => {
          const li = row(item.label);
          const chosen = selected?.id === item.id;
          const select = button(!item.eligible ? "Prepare unattended setup first" : chosen ? "Selected" : "Select revision", () => {
            selected = item; render(); removeButton.focus(); status.textContent = "Profile revision selected.";
          });
          select.setAttribute("aria-label", `${select.textContent}: ${item.label}`);
          select.disabled = !item.eligible || chosen;
          li.append(select); results.append(li);
        });
        nextButton.hidden = !next;
      }
      async function search(after = "") {
        request?.abort();
        const active = new AbortController(); request = active;
        if (!after) query = input.value.trim();
        const endpoint = new URL(root.dataset.source, location.href);
        if (endpoint.origin !== location.origin) return;
        endpoint.searchParams.set("q", query);
        if (after) endpoint.searchParams.set("after", after);
        status.textContent = "Searching Platform SSO profiles…"; nextButton.disabled = true;
        try {
          const response = await fetch(endpoint, { signal: active.signal, credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
          if (!response.ok) throw new Error("search failed");
          const data = await response.json();
          if (!Array.isArray(data.items) || data.items.length > 25 || typeof data.next !== "string" || !data.items.every(item => typeof item.id === "string" && typeof item.profile === "string" && typeof item.label === "string" && typeof item.eligible === "boolean")) throw new Error("invalid search");
          if (request !== active || !root.isConnected) return;
          options = data.items; next = data.next; render();
          status.textContent = options.length ? `${options.length} matching profile(s). Profiles marked for preparation must first be updated in the profile editor.` : "No matching profiles. Your selection is retained.";
        } catch (error) {
          if (request !== active || error.name === "AbortError" || !root.isConnected) return;
          options = []; next = ""; render();
          status.textContent = "Profiles could not be loaded. Retry the search. Your selection is retained.";
        } finally { if (request === active) nextButton.disabled = false; }
      }
      root.querySelector("[data-sso-find]").addEventListener("click", () => search());
      nextButton.addEventListener("click", () => search(next));
      input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); search(); } });
      render();
    });
  }
  window.openUEMADEPlatformSSO = initialize;
  document.addEventListener("DOMContentLoaded", initialize);
  document.addEventListener("htmx:afterSwap", initialize);
  initialize();
})();
