export default async function run(browser,record) {
 const {visit,evaluate,check,enter,capture}=browser;
 for(const state of ["install","remove","pending","delivered","observed","restart","uncertain","reader","cancelled","expired","failed","not-started"]) for(const width of [390,768,1440]) {
  await visit("windows-dispatch-"+state,width);
  check(await evaluate("!document.querySelector('main img, main iframe')"),"Dispatch data injected markup");
  if(["install","remove"].includes(state)) {
   check(await evaluate("document.querySelector('main').textContent.includes('Dispatch is not proof of installation or removal')"),"Review implied success");
   check(await evaluate("!document.querySelector('main input[name=source_url],main input[name=arguments],main input[name=operation]')"),"Review allowed private intent changes");
   if(state==="remove") check(await evaluate("document.querySelector('main').textContent.includes('Application data may be affected')"),"Removal impact omitted");
   await evaluate(`window.f=document.querySelector('main form');window.submissions=[];
    f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push({path:new URL(f.action).pathname,fields:Object.fromEntries(new FormData(f))})},true);f.requestSubmit()`);
   check(await evaluate("submissions.length===0"),"Dispatch bypassed explicit confirmation");
   await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");await enter();
   const submissions=await evaluate("submissions");
   check(submissions.length===1&&submissions[0].path==="/tenant/1/software/catalog/90000000-0000-4000-8000-000000000030/windows-requests/90000000-0000-4000-8000-000000000033/dispatch","Dispatch lost exact scope and preparation");
   const fields=submissions[0].fields;
   check(fields.dispatch_id==="90000000-0000-4000-8000-000000000039"&&fields.review_hash==="a".repeat(64)&&fields.csrf==="test-csrf-token"&&fields.confirmed==="yes","Dispatch lost bound review or CSRF");
  } else {
   check(await evaluate("!document.querySelector('main a[href$=dispatch]')"),"History allowed another dispatch of the same preparation");
   const cancel=await evaluate("!!document.querySelector('main form[action$=\"dispatch/cancel\"]')");
   check(cancel===(state==="pending"),"Cancellation was available after delivery or for a reader");
   if(state==="reader") check(await evaluate("!document.querySelector('main form')"),"Reader received mutation controls");
   if(["restart","uncertain"].includes(state)) check(await evaluate("document.querySelector('main').textContent.includes('another operation is blocked')"),"Incomplete execution presented as complete");
   if(state==="pending") {
    await evaluate(`window.f=document.querySelector('main form[action$="dispatch/cancel"]');window.submissions=[];f.addEventListener('submit',e=>{e.preventDefault();e.stopImmediatePropagation();submissions.push(Object.fromEntries(new FormData(f)))},true);f.requestSubmit()`);
    check(await evaluate("submissions.length===0"),"Queued cancellation bypassed review");
    await evaluate("f.elements.confirmed.checked=true;f.querySelector('button').focus()");await enter();
    check(await evaluate("submissions.length===1&&submissions[0].csrf==='test-csrf-token'&&submissions[0].confirmed==='yes'"),"Queued cancellation lost confirmation or CSRF");
   }
  }
  check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows dispatch page overflow");
  if(width===390&&["remove","restart","reader"].includes(state)){await evaluate("window.scrollTo(0,0)");await capture("windows-dispatch-"+state+"-390")}
  record({name:"Windows dispatch "+state,width,passed:true});
 }
}
