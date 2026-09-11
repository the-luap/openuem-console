// GET submissions stay on the owned read-only fixture server.
import { checkCurrentLink } from "./inventory-navigation.mjs";
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const role of ["viewer", "operator"])
    for (const state of ["first", "next", "empty", "long"])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-memory-" + state + "-" + role, width);
        await checkCurrentLink(browser, "Computer inventory", "Reported memory modules");
        check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip]').length === 0 && !window.__ownedMemoryMarkup`), "Memory report injected markup, rich tooltips or mutation controls");
        check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent === 'Reported memory modules'`), "Memory navigation lost its active page");
        check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Report label and timestamp ran together");
        const links = await evaluate(`(() => {
          const links = [...document.querySelectorAll('nav[aria-label="Memory module pages"] a')];
          return links.map(a => ({text:a.textContent, path:new URL(a.href).pathname, query:Object.fromEntries(new URL(a.href).searchParams)}));
        })()`);
        const path = "/tenant/1/site/1/computers/desktop-report/inventory/memory";
        const next = links.find(a => a.text === "Next page");
        check(Boolean(next) === (state !== "empty"), "Memory page continuation changed");
        if (next)
          check(next.path === path && next.query.q === "%_& Example" && next.query.after === (state === "next" ? "50" : "25"), "Next page lost scope, literal search or cursor");
        const first = links.find(a => a.text === "First page");
        check(Boolean(first) === (state === "next" || state === "empty"), "First-page recovery missing");
        if (first) check(first.path === path && first.query.q === "%_& Example" && !first.query.after, "First page lost scope or retained a stale cursor");
        check(await evaluate(`(() => {const link=[...document.querySelectorAll('main a')].find(a=>a.textContent==='Clear search');const url=new URL(link.href);return url.pathname==='${path}' && url.search==='';})()`), "Clear search retained a cursor or query");
        if (state === "empty") {
          check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no memory modules') && document.querySelectorAll('main article').length===0`), "Empty memory report misrepresented");
        } else {
          const entry = await evaluate(`(() => {
            const card=document.querySelector('main article');
            return {name:card.querySelector('h3').textContent, fields:Object.fromEntries([...card.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent]))};
          })()`);
          const marker = '<img src="data:," onerror="window.__ownedMemoryMarkup=true">';
          check(entry.name === marker + (state === "long" ? "MemoryReport".repeat(50) : ""), "Literal reported module name lost");
          const expected = {
            "Reported capacity":"16 GB", "Reported memory type":"DDR5",
            "Serial number":marker+(state==="long"?"SerialReport".repeat(50):""),
            "Part number":state==="long"?"LongPart".repeat(50):"Part & Module",
            "Reported speed":"4800 MT/s", "Manufacturer":"Example & Partners",
          };
          check(JSON.stringify(entry.fields) === JSON.stringify(expected), "Reported memory module values changed");
          check(await evaluate(`(() => {const missing=document.querySelectorAll('main article')[1];return missing.querySelector('h3').textContent==='Not reported' && Array.from(missing.querySelectorAll('dd')).every(dd=>dd.textContent==='Not reported');})()`),"Absent memory fields became observations");
        }
        await evaluate(`
          window.f=document.querySelector('main form');window.posts=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();
            posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]});},true);
          f.elements.q.value='%_& New module';f.elements.q.focus();
        `);
        await enter();
        const posts = await evaluate("posts");
        check(posts.length === 1 && posts[0].method === "get" && posts[0].path === path && posts[0].fields.length === 1 && posts[0].fields[0][0] === "q" && posts[0].fields[0][1] === "%_& New module", "Keyboard search changed scope or retained old pagination");
        check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Memory page overflow");
        if (width === 390 && role === "viewer" && ["first", "long", "empty"].includes(state)) {
          await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
          await capture("desktop-memory-" + state + "-390");
        }
        record({name:"Desktop memory " + role + " " + state,width,passed:true});
      }
}
