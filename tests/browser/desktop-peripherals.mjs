// Forms are intercepted on the owned fixture server; no device is contacted.
import { checkCurrentLink } from "./inventory-navigation.mjs";
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const kind of ["monitors", "printers"])
    for (const role of ["viewer", "operator"])
      for (const state of ["first", "next", "empty", "long"])
        for (const width of [390, 768, 1440]) {
          await visit(`desktop-peripherals-${kind}-${state}-${role}`, width);
          await checkCurrentLink(browser, "Computer inventory", "Reported peripherals");
          await checkCurrentLink(browser, "Peripheral reports", kind === "monitors" ? "Monitors" : "Printers");
          check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip]').length===0 && !window.__ownedPeripheralsMarkup`), "Peripherals report injected markup or mutation controls");
          check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent==='Reported peripherals'`), "Peripherals navigation lost its active page");
          check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Peripherals report label and timestamp ran together");
          const path = "/tenant/1/site/1/computers/desktop-report/inventory/peripherals";
          const kinds = await evaluate(`Array.from(document.querySelectorAll('nav[aria-label="Peripheral reports"] a'),a=>({current:a.getAttribute('aria-current'),path:new URL(a.href).pathname,query:Object.fromEntries(new URL(a.href).searchParams)}))`);
          check(kinds.length===2 && kinds.every(a=>a.path===path && Object.keys(a.query).length===1 && (a.current==='page')===(a.query.kind===kind)), "Changing peripherals kind retained stale search, cursor or scope");
          const links = await evaluate(`Array.from(document.querySelectorAll('nav[aria-label="Peripheral pages"] a'),a=>({text:a.textContent,path:new URL(a.href).pathname,query:Object.fromEntries(new URL(a.href).searchParams)}))`);
          const next = links.find(a=>a.text==='Next page');
          check(Boolean(next)===(state!=="empty"),"Peripherals continuation changed");
          if(next) check(next.path===path && next.query.kind===kind && next.query.q==="%_& Example" && next.query.after===(state==="next"?"50":"25"),"Peripherals continuation lost kind, scope, search or cursor");
          const first = links.find(a=>a.text==='First page');
          check(Boolean(first)===(state==="next"||state==="empty"),"Peripherals first-page recovery missing");
          if(first) check(first.path===path && first.query.kind===kind && first.query.q==="%_& Example" && !first.query.after,"First peripherals page retained stale cursor or lost search");
          check(await evaluate(`(()=>{const a=Array.from(document.querySelectorAll('main a')).find(a=>a.textContent==='Clear search');const url=new URL(a.href);return url.pathname==='${path}' && url.searchParams.get('kind')==='${kind}' && [...url.searchParams].length===1;})()`),"Clearing peripherals search lost kind or retained cursor");
          if(state==="empty") {
            check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no displays or printers') && document.querySelectorAll('main article').length===0`),"Empty peripherals report misrepresented");
          } else {
            const cards = await evaluate(`Array.from(document.querySelectorAll('main article'),card=>({name:card.querySelector('h3').textContent,fields:Object.fromEntries(Array.from(card.querySelectorAll('dt'),dt=>[dt.textContent,dt.nextElementSibling.textContent]))}))`);
            const marker = '<img src="data:," onerror="window.__ownedPeripheralsMarkup=true">';
            check(cards[0].name===marker+(state==="long"?"PeripheralsReport".repeat(50):""),"Literal reported peripheral name lost");
            const expected = kind==="monitors" ? {
              "Manufacturer":"Example & Partners Displays", "Serial number":marker+(state==="long"?"SerialReport".repeat(50):""),
              "Reported manufacture week":"07", "Reported manufacture year":"2024",
            } : {
              "Reported port":marker+(state==="long"?"PortReport".repeat(50):""), "Default printer":"Yes", "Network printer":"No", "Shared printer":"Not reported",
            };
            check(JSON.stringify(cards[0].fields)===JSON.stringify(expected),"Reported peripheral values changed");
            check(cards[1].name==='Not reported' && Object.values(cards[1].fields).every(v=>v==='Not reported'),"Absent peripheral values became observations");
            if(kind==="printers") {
              check(cards.length===3 && cards[2].fields['Default printer']==='No' && cards[2].fields['Network printer']==='Yes' && cards[2].fields['Shared printer']==='No',"Reported printer flags were conflated with missing flags");
            } else check(cards.length===2,"Monitor reports changed");
          }
          await evaluate(`window.f=document.querySelector('main form');window.submissions=[];
            f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({method:f.method,path:new URL(f.action).pathname,query:new URL(f.action).search,fields:[...new FormData(f)]});},true);
            f.elements.q.value='%_& New peripheral';f.elements.q.focus();`);
          await enter();
          const submissions=await evaluate("submissions");
          check(submissions.length===1 && submissions[0].method==='get' && submissions[0].path===path && submissions[0].query==='' && JSON.stringify(submissions[0].fields)===JSON.stringify([['kind',kind],['q','%_& New peripheral']]),"Keyboard peripherals search changed scope, kind or retained pagination");
          check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),"Peripherals page overflow");
          if(width===390 && role==='viewer' && ['first','long','empty'].includes(state)) {
            await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
            await capture(`desktop-peripherals-${kind}-${state}-390`);
          }
          record({name:`Desktop peripherals ${kind} ${role} ${state}`,width,passed:true});
        }
}
