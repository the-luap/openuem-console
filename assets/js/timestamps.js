// Format instants using the catalog selected by the server. UTC is explicit;
// device-local deadline strings are never selected or converted by this script.
(() => {
  if (globalThis.uemTimestampsReady) return;
  globalThis.uemTimestampsReady = true;
  const selector = "time[data-uem-timestamp]";
  const formatters = new Map();
  function format(node) {
    const value = node.getAttribute("datetime");
    if (!value) return;
    const instant = new Date(value);
    if (!Number.isFinite(instant.getTime())) return;
    const locale = node.lang || document.documentElement.lang || "en";
    const seconds = node.getAttribute("data-uem-precision") === "second";
    const key = locale + (seconds ? "/second" : "/minute");
    try {
      let formatter = formatters.get(key);
      if (!formatter) {
        formatter = new Intl.DateTimeFormat(locale, {
          year: "numeric", month: "short", day: "numeric",
          hour: "2-digit", minute: "2-digit", timeZone: "UTC",
          ...(seconds ? { second: "2-digit" } : {}),
        });
        if (formatters.size < 16) formatters.set(key, formatter);
      }
      const text = formatter.format(instant) + " UTC";
      if (node.textContent !== text) node.textContent = text;
    } catch {
      // Unsupported locales or Intl implementations retain the server's UTC text.
    }
  }
  function render(root) {
    if (root.nodeType === Node.ELEMENT_NODE && root.matches(selector)) format(root);
    if (root.querySelectorAll) root.querySelectorAll(selector).forEach(format);
  }
  render(document);
  new MutationObserver(records => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE && node.isConnected) render(node);
      }
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
})();
