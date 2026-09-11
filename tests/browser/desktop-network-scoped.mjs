// GET submissions stay on the owned read-only fixture server.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const role of ["viewer", "operator"])
    for (const state of ["first", "next", "empty", "long"])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-network-scoped-" + state + "-" + role, width);
        check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip]').length === 0 && !window.__ownedNetworkMarkup`), "Network report injected markup, rich tooltips or mutation controls");
        check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent === 'Reported network'`), "Network navigation lost its active page");
        check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Report label and timestamp ran together");
        const links = await evaluate(`(() => {
          const links = [...document.querySelectorAll('nav[aria-label="Network pages"] a')];
          return links.map(a => ({text:a.textContent, path:new URL(a.href).pathname, query:Object.fromEntries(new URL(a.href).searchParams)}));
        })()`);
        const path = "/tenant/1/site/1/computers/desktop-report/inventory/network";
        const next = links.find(a => a.text === "Next page");
        check(Boolean(next) === (state !== "empty"), "Network page continuation changed");
        if (next)
          check(next.path === path && next.query.q === "%_& Example" && next.query.after === (state === "next" ? "50" : "25"), "Next page lost scope, literal search or cursor");
        const first = links.find(a => a.text === "First page");
        check(Boolean(first) === (state === "next" || state === "empty"), "First-page recovery missing");
        if (first) check(first.path === path && first.query.q === "%_& Example" && !first.query.after, "First page lost scope or retained a stale cursor");
        check(await evaluate(`(() => {const link=[...document.querySelectorAll('main a')].find(a=>a.textContent==='Clear search');const url=new URL(link.href);return url.pathname==='${path}' && url.search==='';})()`), "Clear search retained a cursor or query");
        if (state === "empty") {
          check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no network adapters') && document.querySelectorAll('main article').length===0`), "Empty network report misrepresented");
        } else {
          const entry = await evaluate(`(() => {
            const card=document.querySelector('main article');
            return {name:card.querySelector('h3').textContent, fields:Object.fromEntries([...card.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent]))};
          })()`);
          const marker = '<img src="data:," onerror="window.__ownedNetworkMarkup=true">';
          check(entry.name === marker + (state === "long" ? "NetworkReport".repeat(50) : ""), "Literal reported adapter name lost");
          const expected = {
            "MAC address":"AA:BB:CC:DD:EE:FF", "IP addresses":"192.0.2.1, 2001:db8::1",
            "Subnet":"255.255.255.0", "Default gateway":"192.0.2.254",
            "DNS servers":marker + (state === "long" ? "DNSReport".repeat(50) : ""),
            "DNS domain":state === "long" ? "LongDomain".repeat(50) : "Example & Partners.test",
            "DHCP enabled":"Not reported", "Link speed":"1 Gbps", "Virtual adapter":"No",
          };
          check(JSON.stringify(entry.fields) === JSON.stringify(expected), "Reported network values or absent flags changed");
        }
        await evaluate(`
          window.f=document.querySelector('main form');window.posts=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();
            posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]});},true);
          f.elements.q.value='%_& New adapter';f.elements.q.focus();
        `);
        await enter();
        const posts = await evaluate("posts");
        check(posts.length === 1 && posts[0].method === "get" && posts[0].path === path && posts[0].fields.length === 1 && posts[0].fields[0][0] === "q" && posts[0].fields[0][1] === "%_& New adapter", "Keyboard search changed scope or retained old pagination");
        check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Network page overflow");
        if (width === 390 && role === "viewer" && ["first", "long", "empty"].includes(state)) {
          await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
          await capture("desktop-network-scoped-" + state + "-390");
        }
        record({name:"Desktop network " + role + " " + state,width,passed:true});
      }
}
