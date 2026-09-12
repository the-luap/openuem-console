export default async function run(browser,record) {
 for(const state of ['choose','empty','preview','existing','excluded','assignment','history','empty-history','long'])for(const width of [390,768,1440]){
  await browser.visit('apple-update-group-'+state,width);
  const view=await browser.evaluate(`(()=>{
   const main=document.querySelector('[data-update-groups]');window.updateGroupForm=main.querySelector('[data-update-group-confirm]');
   return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:main.textContent,form:!!updateGroupForm,required:updateGroupForm?.elements.confirmed.required,inputs:updateGroupForm?[...updateGroupForm.querySelectorAll('input')].map(e=>({name:e.name,type:e.type})):[],links:[...main.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))};
  })()`);
  browser.check(view.width<=view.viewport+1,'Apple update group overflows viewport');
  if(['preview','existing','long'].includes(state)){
   browser.check(view.form&&view.required&&view.inputs.every(e=>e.type===(e.name==='confirmed'?'checkbox':'hidden')),'Reviewed update selection is editable or lacks confirmation');
   await browser.evaluate(`(()=>{updateGroupForm.addEventListener('submit',event=>{event.preventDefault();window.updateFields=Object.fromEntries(new FormData(updateGroupForm,event.submitter));});updateGroupForm.querySelector('button').focus();})()`);
   await browser.enter();browser.check(await browser.evaluate('!window.updateFields'),'Unchecked group update submitted');
   await browser.evaluate("updateGroupForm.elements.confirmed.checked=true;updateGroupForm.querySelector('button').focus()");await browser.enter();
   const fields=await browser.evaluate('window.updateFields');
   browser.check(fields&&fields.expected_revision==='2'&&fields.group_revision==='3'&&fields.group_id==='30000000-0000-0000-0000-000000000001'&&fields.request_key==='50000000-0000-0000-0000-000000000001'&&fields.devices==='10000000-0000-0000-0000-000000000001:'+ 'a'.repeat(64)&&fields.csrf==='owned-csrf'&&fields.confirmed==='yes','Keyboard confirmation lost plan/group revisions, policy token, targets or CSRF');
   browser.check(await browser.evaluate("updateGroupForm.getAttribute('action')==='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001/group-assignments'"),'Update confirmation changed scope or plan');
   if(state==='existing')browser.check(view.text.includes('Existing policy will be replaced: 18.7')&&view.text.includes('22H90')&&view.text.includes('2026-11-01T18:00:00'),'Replacement preview hid the current policy');
   if(state==='preview')browser.check(view.text.includes('No existing update policy.'),'New assignment claimed an existing policy');
  }else browser.check(!view.form,'Read-only group state offers confirmation');
  if(state==='choose'){
   const links=view.links.filter(a=>a.text==='Review this group');browser.check(links.length===1&&view.text.includes('Archived; unavailable'),'Archived group offers work');
   const url=new URL(links[0].href,'http://fixture');browser.check(url.pathname.endsWith('/groups/30000000-0000-0000-0000-000000000001/preview')&&url.searchParams.get('revision')==='2'&&url.searchParams.get('group_revision')==='3','Chooser lost source revisions');
  }
  if(state==='empty')browser.check(view.text.includes('No dynamic groups'),'Empty chooser lost its explanation');
  if(state==='excluded')browser.check(view.text.includes('No members can receive')&&view.text.includes('Owned Windows'),'All-excluded preview lost its explanation');
  if(state==='assignment')browser.check(view.text.includes('Original group update assignment')&&view.text.includes('Owned <update pilot>')&&view.text.includes('60000000-0000-0000-0000-000000000001')&&view.links.some(a=>a.href==='/tenant/1/site/1/ios/10000000-0000-0000-0000-000000000001'),'Original receipt lost source, command or device navigation');
  if(state==='history')browser.check(view.links.some(a=>a.text==='Older assignments'&&a.href.endsWith('?before=40000000-0000-0000-0000-000000000001')),'History lost its scoped cursor');
  if(state==='empty-history')browser.check(view.text.includes('No confirmed group updates')&&!view.links.some(a=>a.text==='Older assignments'),'Empty history offers more results');
  if(width===390)await browser.capture('apple-update-group-'+state+'-390');record({name:'Apple update group '+state,width,passed:true});
 }
}
