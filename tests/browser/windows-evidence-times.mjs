export default async function run(browser,record) {
 const {visit,evaluate,check,capture}=browser;
 for(const state of ["valid","renewal_due","expires_soon","expired","retired","empty"])
  for(const width of [390,768,1440]) {
   await visit("windows-health-"+state,width);
   check(await evaluate(`!document.querySelector('main script,main form[method="post"]')`),"Health evidence injected markup or mutation controls");
   const assessment=await evaluate(`document.querySelector('main time').textContent`);
   check(assessment.includes("Sep") && assessment.includes("2026") && assessment.includes("12:13:14.123456") && assessment.endsWith(" UTC"),"Health assessment lost localized subsecond evidence");
   check(await evaluate(`document.querySelector('main').textContent.includes('Expiry assessed at ') && document.querySelector('main').textContent.includes('does not confirm that Windows has scheduled a renewal')`),"Assessment label or uncertainty changed");
   if(state==="empty")check(await evaluate(`document.querySelector('main').textContent.includes('No devices match')`),"Empty health scope lost its explanation");
   else {
    check(await evaluate(`document.querySelector('main').textContent.includes('<script>Device</script>')`),"Reported device name was not literal");
    const links=await evaluate(`[...document.querySelectorAll('main a')].map(a=>({text:a.textContent,path:new URL(a.href).pathname}))`);
    check(links.some(link=>link.path==='/tenant/1/site/11/windows/10000000-0000-4000-8000-000000000001/renewals'),"Health device link lost its actual site");
    check(links.some(link=>link.text==='Review pending replacement')===["expired","renewal_due"].includes(state),"Pending certificate evidence was conflated with confirmation");
   }
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows certificate health page overflows");
   if(width===390 && ["expired","empty"].includes(state))await capture("windows-health-"+state+"-390");
   record({name:"Windows health times "+state,width,passed:true});
  }
 for(const state of ["pending","sent","uncertain","verified","removed"])
  for(const width of [390,768,1440]) {
   await visit("windows-update-"+state,width);
   check(await evaluate(`!document.querySelector('main script') && document.querySelector('main').textContent.includes('Policy <script>unsafe</script>')`),"Update policy report injected markup");
   check(await evaluate(`document.querySelector('main').textContent.includes('They do not prove patch download') && document.querySelector('main').textContent.includes('do not continuously check')`),"Update report claimed stronger evidence");
   check(await evaluate(`document.querySelectorAll('main time[data-uem-timestamp]').length>0 && [...document.querySelectorAll('main time[data-uem-timestamp]')].every(node=>node.textContent.includes('UTC'))`),"Update evidence lost explicit timestamp zones");
   const mutation=await evaluate(`(()=>{const form=document.querySelector('main form[method="post"]');return form?{path:new URL(form.action).pathname,token:form.elements.csrf.value,confirmation:form.elements.confirm_cancel.required}:null;})()`);
   check(Boolean(mutation)===(state==="pending"),"Already-sent update work became cancelable");
   if(mutation)check(mutation.path==="/tenant/1/site/11/windows/10000000-0000-4000-8000-000000000001/updates/20000000-0000-4000-8000-000000000001/cancel" && mutation.token==="synthetic-csrf" && mutation.confirmation,"Update cancellation lost scope, token or confirmation");
   if(state==="removed")check(await evaluate(`document.querySelector('main').textContent.includes('another source may remain')`),"Removal erased another policy source's uncertainty");
   check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Windows update evidence page overflows");
   if(width===390 && ["pending","removed"].includes(state))await capture("windows-update-"+state+"-390");
   record({name:"Windows update times "+state,width,passed:true});
  }
}
