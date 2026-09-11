export default async function run(browser,record) {
 const {visit,evaluate,check,enter,capture}=browser;
 for(const state of ["prepared","reader","cancelled","expired","withdrawn","empty"]) for(const width of [390,768,1440]) {
  await visit("windows-requests-"+state,width);
  check(await evaluate("document.querySelector('main').textContent.includes('These preparations expire without automatic execution')"),"Preparation implied automatic installation");
  check(await evaluate("!document.querySelector('main img, main iframe')"),"Device or actor data injected markup");
  if(state==="reader") check(await evaluate("!document.querySelector('main form')"),"Reader received mutation or device selection controls");
  if(["cancelled","expired","empty"].includes(state)) check(await evaluate("!document.querySelector('main form[action$=cancel]')"),"Terminal or missing request could be cancelled");
  if(state==="withdrawn") check(await evaluate("!document.querySelector('main select[name=device]') && document.querySelector('main form[action$=cancel]')!==null"),"Withdrawal lost history cancellation or allowed new preparation");
  if(state==="prepared") {
   await evaluate(`window.f=[...document.querySelectorAll('main form')].find(f=>f.elements.request_id);window.submissions=[];
    f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({path:new URL(f.action).pathname,fields:Object.fromEntries(new FormData(f))})},true);
    f.elements.device.value='90000000-0000-4000-8000-000000000032';f.elements.operation.value='remove';f.requestSubmit();`);
   check(await evaluate("submissions.length===0"),"Preparation bypassed confirmation");
   await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");
   await enter();
   const submissions=await evaluate("submissions");
   check(submissions.length===1 && submissions[0].path==="/tenant/1/software/catalog/90000000-0000-4000-8000-000000000030/windows-requests","Preparation changed version or organization");
   const fields=submissions[0].fields;
   check(fields.device==="90000000-0000-4000-8000-000000000032" && fields.operation==="remove" && fields.request_id==="90000000-0000-4000-8000-000000000031" && fields.csrf==="test-csrf-token" && fields.confirmed==="yes","Preparation lost exact intent");
   const links=await evaluate(`[...document.querySelectorAll('main a')].filter(a=>['More matching Windows devices','Older requests'].includes(a.textContent)).map(a=>({name:a.textContent,params:Object.fromEntries(new URL(a.href).searchParams)}))`);
   check(links.length===2 && links.every(l=>l.params.q==="%_&"),"Paging lost literal search");
   check(links.find(l=>l.name==="Older requests").params.after==="90000000-0000-4000-8000-000000000037" && links.find(l=>l.name==="More matching Windows devices").params.before==="90000000-0000-4000-8000-000000000038","Independent page cursors were lost");
   await evaluate(`window.f=document.querySelector('main form[action$=cancel]');window.submissions=[];f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push(Object.fromEntries(new FormData(f)))},true);f.requestSubmit()`);
   check(await evaluate("submissions.length===0"),"Cancellation bypassed confirmation");
   await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");
   await enter();
   check(await evaluate("submissions.length===1 && submissions[0].csrf==='test-csrf-token' && submissions[0].confirmed==='yes'"),"Keyboard cancellation lost CSRF");
  }
  check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows requests page overflow");
  if(width===390 && ["prepared","reader"].includes(state)) {await evaluate("window.scrollTo(0,0)");await capture("windows-requests-"+state+"-390")}
  record({name:"Windows requests "+state,width,passed:true});
 }
}
