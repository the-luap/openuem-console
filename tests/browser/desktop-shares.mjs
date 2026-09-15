// GET submissions stay on the owned read-only fixture server.
import { checkCurrentLink } from "./inventory-navigation.mjs";
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const role of ["viewer", "operator"])
    for (const state of ["first", "next", "empty", "long"])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-shares-" + state + "-" + role, width);
        await checkCurrentLink(browser, "Computer inventory", "Reported shares");
        check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip],article a').length === 0 && !window.__ownedSharesMarkup && !window.__ownedSharesPath`), "Shares report injected markup, rich tooltips or mutation controls");
        check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent === 'Reported shares'`), "Shares navigation lost its active page");
        check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Report label and timestamp ran together");
        const links = await evaluate(`(() => {
          const links = [...document.querySelectorAll('nav[aria-label="Share pages"] a')];
          return links.map(a => ({text:a.textContent, path:new URL(a.href).pathname, query:Object.fromEntries(new URL(a.href).searchParams)}));
        })()`);
        const path = "/tenant/1/site/1/computers/desktop-report/inventory/shares";
        const next = links.find(a => a.text === "Next page");
        check(Boolean(next) === (state !== "empty"), "Shares page continuation changed");
        if (next)
          check(next.path === path && next.query.q === "%_& Example" && next.query.after === (state === "next" ? "50" : "25"), "Next page lost scope, literal search or cursor");
        const first = links.find(a => a.text === "First page");
        check(Boolean(first) === (state === "next" || state === "empty"), "First-page recovery missing");
        if (first) check(first.path === path && first.query.q === "%_& Example" && !first.query.after, "First page lost scope or retained a stale cursor");
        check(await evaluate(`(() => {const link=[...document.querySelectorAll('main a')].find(a=>a.textContent==='Clear search');const url=new URL(link.href);return url.pathname==='${path}' && url.search==='';})()`), "Clear search retained a cursor or query");
        if (state === "empty") {
          check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no shares') && document.querySelectorAll('main article').length===0`), "Empty shares report misrepresented");
        } else {
          const entry = await evaluate(`(() => {
            const card=document.querySelector('main article');
            return {name:card.querySelector('h3').textContent, fields:Object.fromEntries([...card.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent]))};
          })()`);
          const marker = '<img src="data:," onerror="window.__ownedSharesMarkup=true">';
          check(entry.name === marker + (state === "long" ? "SharesReport".repeat(50) : ""), "Literal reported share name lost");
          const expected = {
            "Reported description": marker+(state==="long"?"DescriptionReport".repeat(50):""),
            "Reported path": String.raw`\\server\share`+(state==="long"?"LongPath".repeat(50):""),
          };
          check(JSON.stringify(entry.fields) === JSON.stringify(expected), "Reported share values changed");
          check(await evaluate(`(() => {const missing=document.querySelectorAll('main article')[1];return missing.querySelector('h3').textContent==='Not reported' && Array.from(missing.querySelectorAll('dd')).every(dd=>dd.textContent==='Not reported');})()`),"Absent shares fields became observations");
        }
        await evaluate(`
          window.f=document.querySelector('main form');window.posts=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();
            posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]});},true);
          f.elements.q.value='%_& New share';f.elements.q.focus();
        `);
        await enter();
        const posts = await evaluate("posts");
        check(posts.length === 1 && posts[0].method === "get" && posts[0].path === path && posts[0].fields.length === 1 && posts[0].fields[0][0] === "q" && posts[0].fields[0][1] === "%_& New share", "Keyboard search changed scope or retained old pagination");
        check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Shares page overflow");
        if (width === 390 && role === "viewer" && ["first", "long", "empty"].includes(state)) {
          await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
          await capture("desktop-shares-" + state + "-390");
        }
        record({name:"Desktop shares " + role + " " + state,width,passed:true});
      }
}
