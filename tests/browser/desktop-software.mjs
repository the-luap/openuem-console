// The fixture server remains read-only; native GET submissions are intercepted.
import { checkCurrentLink } from "./inventory-navigation.mjs";
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const role of ["viewer", "operator"])
    for (const state of ["first", "next", "empty", "long"])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-software-" + state + "-" + role, width);
        await checkCurrentLink(browser, "Computer inventory", "Reported software");
        check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"]').length === 0`), "Software report injected markup or mutation controls");
        check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent === 'Reported software'`), "Software navigation lost its active page");
        const links = await evaluate(`(() => {
          const links = [...document.querySelectorAll('nav[aria-label="Software pages"] a')];
          return links.map(a => ({text:a.textContent, path:new URL(a.href).pathname, query:Object.fromEntries(new URL(a.href).searchParams)}));
        })()`);
        const next = links.find(a => a.text === "Next page");
        check(Boolean(next) === (state !== "empty"), "Software page continuation changed");
        if (next)
          check(next.path === "/tenant/1/site/1/computers/desktop-report/inventory/software" && next.query.q === "%_& Example" && next.query.after === (state === "next" ? "50" : "25"), "Next page lost scope, literal search or cursor");
        const first = links.find(a => a.text === "First page");
        check(Boolean(first) === (state === "next" || state === "empty"), "First-page recovery missing");
        if (first) check(first.query.q === "%_& Example" && !first.query.after, "First page retained a stale cursor");
        if (state === "empty")
          check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that no software is installed')`), "Empty software report misrepresented");
        else
          check(await evaluate(`document.querySelector('tbody th').textContent.startsWith('<img src=x onerror=alert(1)>')`), "Literal reported software name lost");
        await evaluate(`
          window.f = document.querySelector('main form'); window.posts=[];
          f.addEventListener('submit', e => { e.preventDefault(); e.stopImmediatePropagation();
            posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]}); },true);
          f.elements.q.value = '%_& New publisher'; f.elements.q.focus();
        `);
        await enter();
        const posts = await evaluate("posts");
        check(posts.length === 1 && posts[0].method === "get" && posts[0].path === "/tenant/1/site/1/computers/desktop-report/inventory/software" && posts[0].fields.length === 1 && posts[0].fields[0][0] === "q" && posts[0].fields[0][1] === "%_& New publisher", "Keyboard search changed scope or retained old pagination");
        check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Software page overflow");
        if (width === 390 && state !== "empty")
          check(await evaluate(`(() => { const region=document.querySelector('[aria-label="Reported software entries"]');
            region.scrollLeft=region.scrollWidth;
            const scrolls=region.scrollLeft>0 && region.tabIndex===0;
            region.scrollLeft=0; return scrolls;
          })()`), "Narrow software table cannot scroll without crushing columns");
        if (width === 390 && role === "viewer" && ["first", "long", "empty"].includes(state)) {
          await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
          await capture("desktop-software-" + state + "-390");
        }
        record({name:"Desktop software " + role + " " + state,width,passed:true});
      }
}
