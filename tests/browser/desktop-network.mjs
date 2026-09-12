export default async function run(browser, record) {
  const { visit, evaluate, check, capture } = browser;
  for (const state of ["injected", "ordinary", "long", "empty"]) {
    for (const width of [390, 768, 1440]) {
      await visit("desktop-network-" + state, width);
      // Exercise the installed UI library if a reported value ever regresses
      // into a rich tooltip. The payload uses only a local inert data URI.
      await evaluate(`(() => {
        for (const cell of document.querySelectorAll('main table td[uk-tooltip]')) {
          cell.focus(); window.UIkit.tooltip(cell).show();
        }
        return new Promise(resolve => setTimeout(resolve, 100));
      })()`);
      check(await evaluate("window.__ownedDNSMarkup !== true && document.querySelectorAll('[data-owned-dns]').length === 0"), "Reported DNS values became executable tooltip markup");
      if (state === "empty") {
        check(await evaluate("!document.querySelector('main table') && document.querySelector('main').textContent.includes('No network adapters information')"), "Missing adapter report lost its empty state");
      } else {
        const dns = await evaluate("document.querySelector('main table td:nth-child(7)').textContent");
        check(dns.includes("DNS servers") && dns.includes("DNS domain"), "DNS data is not labeled as readable text");
        if (state === "injected") {
          check(dns.includes('192.0.2.53<img src="data:," data-owned-dns="server"') && dns.includes('owned.example.test<img src="data:," data-owned-dns="domain"'), "Literal reported DNS markup was hidden or changed");
        } else if (state === "ordinary") {
          check(dns.includes("192.0.2.53, 2001:db8::53") && dns.includes("owned.example.test"), "Reported IPv4, IPv6 or DNS domain was lost");
        } else {
          check(dns.includes("2001:db8:1234:5678::53, ".repeat(35)) && dns.includes("owned-domain-".repeat(30) + ".example.test"), "Long reported DNS values were truncated");
        }
        if (width <= 768) {
          check(await evaluate(`(() => {
            const region=document.querySelector('[aria-label="Reported network adapters"]');
            region.scrollLeft=region.scrollWidth;
            const scrolls=region.tabIndex===0 && region.scrollLeft>0;
            region.scrollLeft=0; return scrolls;
          })()`), "Network columns cannot be reached in the narrow report region");
        }
      }
      check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Reported network adapters overflow the page");
      if (width === 390 && ["ordinary", "injected"].includes(state)) {
        await capture("desktop-network-" + state + "-390");
      }
      record({ name: "Desktop network " + state, width, passed: true });
    }
  }
}
