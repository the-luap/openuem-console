import { checkCurrentLink } from "./inventory-navigation.mjs";

export default async function run(browser, record) {
 const {visit,evaluate,check,enter,space,capture}=browser;
 const states=["fields","fields-empty","device","device-empty","definition-new","definition","definition-conflict","value","value-empty","value-conflict","long","deletion","deletion-completed","deletion-expired","deletion-conflict"];
 for(const state of states) for(const width of [390,768,1440]) {
  await visit("custom-metadata-"+state,width);
  check(await evaluate(`!window.metadataOwned&&!window.draftOwned&&document.querySelectorAll('main script,main iframe,main img').length===0`),"Custom metadata introduced active content");
  if(state.startsWith("device")||state.startsWith("value")||state==="long") await checkCurrentLink(browser,"Computer inventory","Custom fields");
  check(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),"Custom metadata page overflow");
  if(width===390&&(state==="long"||state==="definition-conflict"||state==="deletion")) await capture("custom-metadata-"+state+"-"+width);
  if(state.startsWith("deletion")&&state!=="deletion") {
   check(await evaluate(`!document.querySelector('main form') && !!document.querySelector('main [role="status"],main [role="alert"]')`),"Completed, expired or conflicting deletion still has an active form");
  } else if(state==="deletion") {
   await evaluate(`window.submissions=[];window.f=document.querySelector('main form');f.addEventListener('submit',e=>{e.preventDefault();submissions.push(Object.fromEntries(new FormData(f)))},true);f.querySelector('button').focus();`);
   await enter();check(await evaluate("submissions.length===0"),"Deletion did not require confirmation");
   await evaluate(`f.querySelector('[name="confirm"]').focus()`);await space();await evaluate("f.querySelector('button').focus()");await enter();
   check(await evaluate(`submissions.length===1&&submissions[0].confirm==='delete'&&Object.keys(submissions[0]).sort().join(',')==='confirm,csrf'&&new URL(f.action).pathname==='/tenant/1/admin/metadata/7/deletion/483690a2-f9da-41e8-b9c4-109c642b52de'`),"Deletion lost exact review, scope or CSRF");
  } else if(state.startsWith("definition")) {
   if(state==="definition-conflict") check(await evaluate(String.raw`document.querySelector('#metadata-name').value==='Draft </textarea><script>window.draftOwned=true</script>'&&document.querySelector('#metadata-description').value==='Draft help\nPreserved second line'&&document.querySelector('main').textContent.includes('Currently saved definition')`),"Definition conflict lost draft or current definition");
   await evaluate(`window.submissions=[];window.f=document.querySelector('main form');f.addEventListener('submit',e=>{e.preventDefault();submissions.push(Object.fromEntries(new FormData(f)))},true);f.elements.name.value="Owner's field";f.querySelector('button').focus()`);await enter();
   const sent=await evaluate("submissions");check(sent.length===1&&Object.keys(sent[0]).sort().join(',')==="csrf,description,name,revision","Definition save lost exact fields");
   check(await evaluate(`new URL(f.action).pathname===${JSON.stringify('/tenant/1/admin/metadata/'+(state==='definition-new'?'new':'7'))}`),"Definition save lost organization scope");
  } else if(state.startsWith("value")||state==="long") {
   if(state==="value-conflict"||state==="long") check(await evaluate(String.raw`document.querySelector('#metadata-value').value==='Draft </textarea><script>window.draftOwned=true</script>\nPreserved second line'&&document.querySelector('main').textContent.includes('Currently saved value')`),"Value conflict lost draft or current value");
   await evaluate(`window.submissions=[];window.f=document.querySelector('main form');f.addEventListener('submit',e=>{e.preventDefault();submissions.push(Object.fromEntries(new FormData(f)))},true);f.elements.value.value='';f.querySelector('button').focus()`);await enter();
   check(await evaluate(`submissions.length===1&&submissions[0].value===''&&submissions[0].field_revision==='350542db-5a9f-4a88-97cb-4b70d5f164d1'&&submissions[0].revision==='be421cab-8cc3-4a29-be3b-da1661e36aa2'&&Object.keys(submissions[0]).sort().join(',')==='csrf,field_revision,revision,value'&&new URL(f.action).pathname==='/tenant/1/site/1/computers/metadata-device/metadata/7'`),"Blank value save lost revisions, CSRF or device scope");
   if(state!=="value-empty") {
    await evaluate(`window.clearForm=document.querySelector('main form[action$="/clear"]');window.clears=[];clearForm.addEventListener('submit',e=>{e.preventDefault();clears.push(Object.fromEntries(new FormData(clearForm)))},true);clearForm.querySelector('button').focus()`);await enter();check(await evaluate("clears.length===0"),"Clearing did not require confirmation");
    await evaluate(`clearForm.querySelector('[name="confirm"]').focus()`);await space();await evaluate("clearForm.querySelector('button').focus()");await enter();
    check(await evaluate(`clears.length===1&&clears[0].confirm==='clear'&&Object.keys(clears[0]).sort().join(',')==='confirm,csrf,field_revision,revision'`),"Clear action lost exact intent and revisions");
   }
  } else {
   check(await evaluate(`!document.querySelector('#metadata-value')`),"Field listing revealed value contents");
   check(await evaluate(`document.querySelector('#metadata-search').value==='literal %_'&&[...document.querySelectorAll('main nav a')].some(a=>a.textContent==='First page'&&new URL(a.href).searchParams.get('q')==='literal %_')`),"Field paging lost literal search");
  }
  record({name:"Custom metadata "+state,width,passed:true});
 }
}
