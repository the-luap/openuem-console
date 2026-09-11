// Forms are intercepted on the owned fixture server; no device is contacted.
export default async function run(browser, record) {
  const { visit, evaluate, check, enter, capture } = browser;
  for (const kind of ["physical", "logical"])
    for (const role of ["viewer", "operator"])
      for (const state of ["first", "next", "empty", "long"])
        for (const width of [390, 768, 1440]) {
          await visit(`desktop-storage-${kind}-${state}-${role}`, width);
          check(await evaluate(`document.querySelector('main').querySelectorAll('img,iframe,form[method="post"],[uk-tooltip]').length===0 && !window.__ownedStorageMarkup`), "Storage report injected markup or mutation controls");
          check(await evaluate(`document.querySelector('nav[aria-label="Computer inventory"] a[aria-current="page"]').textContent==='Reported storage'`), "Storage navigation lost its active page");
          check(await evaluate(`document.querySelector('main section').textContent.includes('Last agent report: Never reported')`), "Storage report label and timestamp ran together");
          const path = "/tenant/1/site/1/computers/desktop-report/inventory/storage";
          const kinds = await evaluate(`Array.from(document.querySelectorAll('nav[aria-label="Storage reports"] a'),a=>({current:a.getAttribute('aria-current'),path:new URL(a.href).pathname,query:Object.fromEntries(new URL(a.href).searchParams)}))`);
          check(kinds.length===2 && kinds.every(a=>a.path===path && Object.keys(a.query).length===1 && (a.current==='page')===(a.query.kind===kind)), "Changing storage kind retained stale search, cursor or scope");
          const links = await evaluate(`Array.from(document.querySelectorAll('nav[aria-label="Storage pages"] a'),a=>({text:a.textContent,path:new URL(a.href).pathname,query:Object.fromEntries(new URL(a.href).searchParams)}))`);
          const next = links.find(a=>a.text==='Next page');
          check(Boolean(next)===(state!=="empty"),"Storage continuation changed");
          if(next) check(next.path===path && next.query.kind===kind && next.query.q==="%_& Example" && next.query.after===(state==="next"?"50":"25"),"Storage continuation lost kind, scope, search or cursor");
          const first = links.find(a=>a.text==='First page');
          check(Boolean(first)===(state==="next"||state==="empty"),"Storage first-page recovery missing");
          if(first) check(first.path===path && first.query.kind===kind && first.query.q==="%_& Example" && !first.query.after,"First storage page retained stale cursor or lost search");
          check(await evaluate(`(()=>{const a=Array.from(document.querySelectorAll('main a')).find(a=>a.textContent==='Clear search');const url=new URL(a.href);return url.pathname==='${path}' && url.searchParams.get('kind')==='${kind}' && [...url.searchParams].length===1;})()`),"Clearing storage search lost kind or retained cursor");
          if(state==="empty") {
            check(await evaluate(`document.querySelector('main [role="status"]').textContent.includes('does not prove that the device has no disks') && document.querySelectorAll('main article').length===0`),"Empty storage report misrepresented");
          } else {
            const cards = await evaluate(`Array.from(document.querySelectorAll('main article'),card=>({name:card.querySelector('h3').textContent,fields:Object.fromEntries(Array.from(card.querySelectorAll('dt'),dt=>[dt.textContent,dt.nextElementSibling.textContent]))}))`);
            const marker = '<img src="data:," onerror="window.__ownedStorageMarkup=true">';
            check(cards[0].name===marker+(state==="long"?"StorageReport".repeat(50):""),"Literal reported disk name lost");
            const expected = kind==="physical" ? {
              "Model":"Example & Partners SSD", "Serial number":marker+(state==="long"?"SerialReport".repeat(50):""), "Reported capacity":"1 TB",
            } : {
              "Volume name":"Data & Archives", "Filesystem":"NTFS", "Reported usage":"37%", "Reported free space":"630 GB",
              "Reported BitLocker status":marker+(state==="long"?"EncryptionReport".repeat(50):""), "Reported capacity":"1 TB",
            };
            check(JSON.stringify(cards[0].fields)===JSON.stringify(expected),"Reported storage values changed");
            if(kind==="logical") {
              check(cards.length===5 && Object.values(cards[1].fields).every(v=>v==='Not reported'),"Missing logical report became an observed value");
              check(cards[2].fields['Reported usage']==='0%',"Stored zero was hidden or changed");
              check(cards[3].fields['Reported usage']==='-1% · Outside the expected range' && cards[4].fields['Reported usage']==='127% · Outside the expected range',"Invalid stored usage was clamped or presented as valid");
              check(await evaluate(`document.querySelector('main section').textContent.includes('Encryption is not verified or enforced here')`),"Reported encryption presented as verified");
            }
          }
          await evaluate(`window.f=document.querySelector('main form');window.submissions=[];
            f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({method:f.method,path:new URL(f.action).pathname,query:new URL(f.action).search,fields:[...new FormData(f)]});},true);
            f.elements.q.value='%_& New disk';f.elements.q.focus();`);
          await enter();
          const submissions=await evaluate("submissions");
          check(submissions.length===1 && submissions[0].method==='get' && submissions[0].path===path && submissions[0].query==='' && JSON.stringify(submissions[0].fields)===JSON.stringify([['kind',kind],['q','%_& New disk']]),"Keyboard storage search changed scope, kind or retained pagination");
          check(await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),"Storage page overflow");
          if(width===390 && role==='viewer' && ['first','long','empty'].includes(state)) {
            await evaluate(`document.querySelector('main section').scrollIntoView({block:'start'});window.scrollBy(0,-150)`);
            await capture(`desktop-storage-${kind}-${state}-390`);
          }
          record({name:`Desktop storage ${kind} ${role} ${state}`,width,passed:true});
        }
}
