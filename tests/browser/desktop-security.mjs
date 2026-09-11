// GET submissions stay on the owned read-only fixture server.
import { checkCurrentLink } from "./inventory-navigation.mjs";
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const role of ["viewer", "operator"])
    for (const state of ["first", "next", "empty", "long", "missing", "negative"])
      for (const width of [390, 768, 1440]) {
        await visit("desktop-security-" + state + "-" + role, width);
        await checkCurrentLink(browser, "Computer inventory", "Reported security");
        check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip],article a').length === 0 && !window.__ownedSecurityMarkup && !window.__ownedSecurityPath`), "Security report injected markup, rich tooltips or mutation controls");
        check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent === 'Reported security'`), "Security navigation lost its active page");
        check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Report label and timestamp ran together");
        const links = await evaluate(`(() => {
          const links = [...document.querySelectorAll('nav[aria-label="Update history pages"] a')];
          return links.map(a => ({text:a.textContent, path:new URL(a.href).pathname, query:Object.fromEntries(new URL(a.href).searchParams)}));
        })()`);
        const path = "/tenant/1/site/1/computers/desktop-report/inventory/security";
        const next = links.find(a => a.text === "Next page");
        check(Boolean(next) === (!["empty","missing"].includes(state)), "Security page continuation changed");
        if (next)
          check(next.path === path && next.query.q === "%_& Example" && next.query.after === (state === "next" ? "50" : "25"), "Next page lost scope, literal search or cursor");
        const first = links.find(a => a.text === "First page");
        check(Boolean(first) === (["next","empty","missing"].includes(state)), "First-page recovery missing");
        if (first) check(first.path === path && first.query.q === "%_& Example" && !first.query.after, "First page lost scope or retained a stale cursor");
        check(await evaluate(`(() => {const link=[...document.querySelectorAll('main a')].find(a=>a.textContent==='Clear search');const url=new URL(link.href);return url.pathname==='${path}' && url.search==='';})()`), "Clear search retained a cursor or query");
        if (["empty","missing"].includes(state)) {
          check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no installed updates') && document.querySelectorAll('main article').length===0`), "Empty security report misrepresented");
        } else {
          const entry = await evaluate(`(() => {
            const card=document.querySelector('main article');
            return {name:card.querySelector('h4').textContent,date:card.querySelector('time')?.dateTime, fields:Object.fromEntries([...card.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent]))};
          })()`);
          const marker = '<img src="data:," onerror="window.__ownedSecurityMarkup=true">';
          check(entry.name === marker + (state === "long" ? "SecurityReport".repeat(50) : ""), "Literal reported update name lost");
          const expectedURL = "https://support.invalid/update?a=1&b=2"+(state==="long"?"LongPath".repeat(50):"");
          check(entry.fields["Reported support URL"] === expectedURL, "Reported support URL changed");
          check(Object.keys(entry.fields).join('|') === "Reported date|Reported support URL", "Update history projection changed");
          if (state === "negative") check(!entry.date && entry.fields["Reported date"] === "Not reported", "Collector zero date became an observation");
          else check(entry.date === "2026-09-01T11:34:56.123456Z", "Reported update instant lost timezone or precision");
          check(await evaluate(`(() => {const missing=document.querySelectorAll('main article')[1];return missing.querySelector('h4').textContent==='Not reported' && Array.from(missing.querySelectorAll('dd')).every(dd=>dd.textContent==='Not reported');})()`),"Absent security fields became observations");
        }
        const summaries = await evaluate(`(() => {
          return [...document.querySelectorAll('main section section')].map(section=>({
            values:Object.fromEntries([...section.querySelectorAll('dt')].map(dt=>[dt.textContent,dt.nextElementSibling.textContent])),
            times:[...section.querySelectorAll('time')].map(t=>t.dateTime),
          }));
        })()`);
        check(summaries.length === 2, "Antivirus and system update reports were combined or omitted");
        const [av, updates] = summaries;
        if (state === "missing") {
          check(Object.values(av.values).every(v=>v==="Not reported") && Object.values(updates.values).every(v=>v==="Not reported") && updates.times.length===0, "Missing security reports became observations");
        } else {
          check(av.values["Reported product"] === "Example & product"+(state==="long"?"ProductReport".repeat(50):""), "Reported antivirus product changed");
          check(av.values["Reported active flag"] === (state==="negative"?"No":"Yes") && av.values["Reported definitions current flag"] === (state==="negative"?"Yes":"No"), "Stored antivirus flags were inverted or conflated");
          check(updates.values["Reported pending updates flag"] === (state==="negative"?"No":"Yes") && updates.values["Reported update status"] === "Unknown & reported", "Stored update flags or literal status changed");
          check(updates.times.length===1 && updates.times[0]==="2026-09-01T11:34:56.123456Z", "Summary instant lost timezone or precision");
          check(updates.values[state==="negative"?"Reported last installation":"Reported last search"] === "Not reported", "Collector zero timestamp became an observation");
        }
        await evaluate(`
          window.f=document.querySelector('main form');window.posts=[];
          f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();
            posts.push({method:f.method,path:new URL(f.action).pathname,fields:[...new FormData(f)]});},true);
          f.elements.q.value='%_& New update';f.elements.q.focus();
        `);
        await enter();
        const posts = await evaluate("posts");
        check(posts.length === 1 && posts[0].method === "get" && posts[0].path === path && posts[0].fields.length === 1 && posts[0].fields[0][0] === "q" && posts[0].fields[0][1] === "%_& New update", "Keyboard search changed scope or retained old pagination");
        check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Security page overflow");
        if (width === 390 && role === "viewer" && ["first", "long", "empty"].includes(state)) {
          await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
          await capture("desktop-security-" + state + "-390");
        }
        record({name:"Desktop security " + role + " " + state,width,passed:true});
      }
}
