(() => {
  "use strict";
  if (window.openUEMRequiredApps) { window.openUEMRequiredApps(); return; }
  function initialize() {
    document.querySelectorAll(".ade-app-picker:not([data-initialized])").forEach(root => {
      root.dataset.initialized = "yes";
      const input = root.querySelector("[data-app-search]");
      const status = root.querySelector("[data-app-status]");
      const results = root.querySelector("[data-app-results]");
      const selectedList = root.querySelector("[data-app-selected]");
      const nextButton = root.querySelector("[data-app-next]");
      const maximum = Number(root.dataset.maximum);
      const selected = new Map();
      const selectedButtons = new Map();
      let options = [], next = "", query = "", request;
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
        selectedButtons.clear();
        selected.forEach(item => {
          const li = row(item.label), hidden = document.createElement("input");
          hidden.type = "hidden"; hidden.name = root.dataset.input; hidden.value = item.id;
          const remove = button("Remove selection", () => {
            selected.delete(item.package); render(); input.focus();
            status.textContent = `${selected.size} revision(s) selected.`;
          });
          remove.setAttribute("aria-label", `Remove ${item.label}`);
          selectedButtons.set(item.id, remove);
          li.append(hidden, remove);
          selectedList.append(li);
        });
        if (!selected.size) selectedList.append(row("No revisions selected."));
        input.setCustomValidity(maximum === 1 && !selected.size ? "Select an approved application revision." : "");
        results.replaceChildren();
        options.forEach(item => {
          const li = row(item.label);
          const chosen = selected.get(item.package);
          const select = button(chosen?.id === item.id ? "Selected" : "Select revision", () => {
            if (maximum === 1) selected.clear();
            selected.set(item.package, item); render();
            status.textContent = `${selected.size} revision(s) selected.`;
            selectedButtons.get(item.id).focus();
          });
          select.setAttribute("aria-label", `${chosen?.id === item.id ? "Selected" : "Select revision"}: ${item.label}`);
          select.disabled = chosen?.id === item.id || maximum > 1 && (!!chosen || selected.size >= maximum);
          li.append(select); results.append(li);
        });
        nextButton.hidden = !next;
      }
      async function search(before = "") {
        request?.abort();
        const active = new AbortController(); request = active;
        if (!before) query = input.value.trim();
        const endpoint = new URL(root.dataset.source, location.href);
        if (endpoint.origin !== location.origin) return;
        endpoint.searchParams.set("q", query);
        if (before) endpoint.searchParams.set("before", before);
        if (root.dataset.package) endpoint.searchParams.set("package", root.dataset.package);
        status.textContent = "Searching approved applications…";
        nextButton.disabled = true;
        try {
          const response = await fetch(endpoint, { signal: active.signal, credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
          if (!response.ok) throw new Error("search failed");
          const data = await response.json();
          if (!Array.isArray(data.items) || data.items.length > 100 || typeof data.next !== "string" || !data.items.every(item => typeof item.id === "string" && typeof item.package === "string" && typeof item.label === "string")) throw new Error("invalid search");
          if (request !== active || !root.isConnected) return;
          options = data.items; next = data.next; render();
          status.textContent = options.length ? `${options.length} matching revision(s). ${selected.size} selected.` : "No approved revisions match this search. Your selections are retained.";
        } catch (error) {
          if (request !== active || error.name === "AbortError") return;
          options = []; next = ""; render();
          status.textContent = "Applications could not be loaded. Retry the search. Your selections are retained.";
        } finally { if (request === active) nextButton.disabled = false; }
      }
      root.querySelector("[data-app-find]").addEventListener("click", () => search());
      nextButton.addEventListener("click", () => search(next));
      input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); search(); } });
      render();
    });
  }
  window.openUEMRequiredApps = initialize;
  document.addEventListener("DOMContentLoaded", initialize);
  document.addEventListener("htmx:afterSwap", initialize);
  initialize();
})();
