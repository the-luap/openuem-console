export default async function run(browser,record) {
 for(const state of ['choose','empty','preview','existing','excluded','assignment','history','progress','receipt-site-operator','preview-site-operator','long','reader'])for(const width of [390,768,1440]) {
  await browser.visit('apple-update-group-organization-'+state,width);
  const v=await browser.evaluate(`(()=>{const m=document.querySelector('[data-update-groups],[data-update-group-progress]');const f=m.querySelector('[data-update-group-confirm]');return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:m.textContent,scripts:m.querySelectorAll('script').length,schedule:!!m.querySelector('[data-update-schedule-confirm]'),form:f?{action:f.getAttribute('action'),fields:Object.fromEntries(new FormData(f)),required:f.elements.confirmed.required}:null,links:[...m.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))}})()`);
  browser.check(v.width<=v.viewport+1&&v.scripts===0,'Organization update group overflows or executes source markup');
  const editable=['preview','existing','long'].includes(state);
  browser.check(v.schedule===editable,'Schedule action does not follow organization and target authority');
  browser.check(!!v.form===editable,'Read-only organization group exposes assignment');
  const profile='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001';
  if(state==='choose'||state==='empty') {
   browser.check(v.text.includes('only within the selected target site')&&v.links.some(a=>a.text==='Site groups'&&a.href.startsWith(profile+'/groups?')&&!a.href.includes('source=organization'))&&v.links.some(a=>a.text==='Manage dynamic groups'&&a.href==='/tenant/1/device-groups'),'Chooser loses source organization or target site');
   if(state==='choose')browser.check(v.links.filter(a=>a.text==='Review this group').length===1&&v.links.some(a=>a.text==='Review this group'&&a.href.includes('source=organization')&&a.href.includes('group_revision=3')),'Organization choice lost source intent or archived exclusion');
   if(state==='empty')browser.check(v.text.includes('No dynamic groups in this organization'),'Empty source is mislabeled as target site');
  } else if(state==='history') {
   browser.check(v.text.includes('Source: organization group · Target site: 1')&&v.links.some(a=>a.text==='Older assignments'&&a.href.startsWith(profile+'/group-assignments?before=')),'History loses source kind or target-site pagination');
  } else {
   browser.check(v.text.includes("Only the selected target site's members are included")&&v.text.includes('Target site: 1 · Organization: 1'),'Preview or receipt hides the source/target intersection');
   const groupLinks=v.links.filter(a=>a.text==='Open the current organization group and its history');
   browser.check(groupLinks.length===(['receipt-site-operator','preview-site-operator','reader'].includes(state)?0:1)&&groupLinks.every(a=>a.href==='/tenant/1/device-groups/30000000-0000-0000-0000-000000000001'),'Historical source links use the wrong scope or bypass organization visibility');
  }
  if(state==='existing')browser.check(v.text.includes('Existing policy will be replaced: 18.7')&&v.text.includes('22H90'),'Organization update hides current policy replacement');
  if(editable) {
   const f=v.form;
   browser.check(f.action===profile+'/group-assignments'&&f.required&&f.fields.group_source==='organization'&&f.fields.expected_revision==='2'&&f.fields.group_revision==='3'&&f.fields.devices==='10000000-0000-0000-0000-000000000001:'+ 'a'.repeat(64)&&f.fields.csrf==='owned-csrf','Reviewed organization source, action or target was lost');
   await browser.evaluate(`(()=>{window.organizationGroupSubmissions=[];const f=document.querySelector('[data-update-group-confirm]');f.addEventListener('submit',e=>{e.preventDefault();window.organizationGroupSubmissions.push(Object.fromEntries(new FormData(f,e.submitter)))});f.querySelector('button').focus()})()`);await browser.enter();
   browser.check(await browser.evaluate('window.organizationGroupSubmissions.length')===0,'Unconfirmed organization update assignment submitted');
   await browser.evaluate("document.querySelector('[data-update-group-confirm]').elements.confirmed.focus()");await browser.space();await browser.tab();await browser.enter();
   const submitted=await browser.evaluate('window.organizationGroupSubmissions');browser.check(submitted.length===1&&submitted[0].confirmed==='yes'&&Object.entries(f.fields).every(([k,value])=>submitted[0][k]===value),'Keyboard assignment changed reviewed intersection');
   const schedule=await browser.evaluate(`(()=>{window.scheduleForm=document.querySelector('[data-update-schedule-confirm]');return {form:!!scheduleForm,required:scheduleForm?.elements.confirmed.required,text:scheduleForm?.parentElement.textContent,action:scheduleForm?.getAttribute('action')};})()`);
   browser.check(schedule.form&&schedule.required&&schedule.text.includes('absolute UTC')&&schedule.text.includes('local to each device')&&schedule.action.endsWith('/schedules'),'Schedule review lost UTC timing, current source or confirmation');
   await browser.evaluate(`(()=>{scheduleForm.addEventListener('submit',event=>{event.preventDefault();window.scheduleFields=Object.fromEntries(new FormData(scheduleForm,event.submitter));});scheduleForm.elements.not_before.value='2026-09-15T18:00:00Z';scheduleForm.querySelector('button').focus();})()`);
   await browser.enter();browser.check(await browser.evaluate('!window.scheduleFields'),'Unchecked schedule submitted');
   await browser.evaluate("scheduleForm.elements.confirmed.checked=true;scheduleForm.elements.not_before.value='2026-09-15T18:00:00+02:00';scheduleForm.querySelector('button').focus()");await browser.enter();
   browser.check(await browser.evaluate('!window.scheduleFields'),'Non-UTC schedule submitted');
   await browser.evaluate("scheduleForm.elements.not_before.value='2026-09-15T18:00:00Z';scheduleForm.querySelector('button').focus()");await browser.enter();
   const scheduled=await browser.evaluate('window.scheduleFields');
   browser.check(scheduled&&scheduled.devices===f.fields.devices&&scheduled.expected_revision===f.fields.expected_revision&&scheduled.group_revision===f.fields.group_revision&&scheduled.request_key===f.fields.request_key&&scheduled.group_source==='organization'&&scheduled.csrf==='owned-csrf'&&scheduled.confirmed==='yes'&&scheduled.not_before==='2026-09-15T18:00:00Z'&&scheduled.activation_window_minutes==='60','Scheduled keyboard confirmation lost exact selection or timing');

  }
  if(width===390){await browser.evaluate("document.querySelector('[data-update-groups],[data-update-group-progress]').scrollIntoView({block:'start'})");await browser.capture('apple-update-group-organization-'+state+'-390');}
  record({name:'Apple organization update group '+state,width,passed:true});
 }
}
