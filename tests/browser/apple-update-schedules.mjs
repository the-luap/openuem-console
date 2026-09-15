export default async function run(browser,record) {
 for(const state of ['scheduled','waiting','activated','blocked','expired','canceled','history','empty-history','long'])for(const width of [390,768,1440]){
  await browser.visit('apple-update-schedule-'+state,width);
  const view=await browser.evaluate(`(()=>{
   const main=document.querySelector('#device-management');window.cancelSchedule=main.querySelector('[data-update-schedule-cancel]');
   return {width:document.documentElement.scrollWidth,viewport:innerWidth,text:main.textContent,form:!!cancelSchedule,required:cancelSchedule?.elements.confirmed.required,links:[...main.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))};
  })()`);
  browser.check(view.width<=view.viewport+1,'Apple schedule overflows viewport');
  if(['scheduled','waiting'].includes(state)){
   browser.check(view.form&&view.required,'Pending schedule lost cancellation confirmation');
   await browser.evaluate(`(()=>{cancelSchedule.addEventListener('submit',event=>{event.preventDefault();window.cancelFields=Object.fromEntries(new FormData(cancelSchedule,event.submitter));});cancelSchedule.querySelector('button').focus();})()`);
   await browser.enter();browser.check(await browser.evaluate('!window.cancelFields'),'Unchecked cancellation submitted');
   await browser.evaluate('cancelSchedule.elements.confirmed.focus()');await browser.space();
   await browser.evaluate("cancelSchedule.querySelector('button').focus()");await browser.enter();
   const fields=await browser.evaluate('window.cancelFields');
   browser.check(fields&&fields.csrf==='owned-csrf'&&fields.confirmed==='yes'&&fields.expected_revision===(state==='waiting'?'2':'1'),'Cancellation lost current revision or CSRF');
   browser.check(await browser.evaluate("cancelSchedule.getAttribute('action')==='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001/schedules/80000000-0000-0000-0000-000000000001/cancel'"),'Cancellation changed site, plan or schedule');
  }else browser.check(!view.form,'Terminal or history page offers cancellation');
  if(!['history','empty-history'].includes(state))browser.check(view.text.includes('2026-09-12 13:00:00')&&view.text.includes('2026-09-12 14:00:00')&&view.text.includes('10000000-0000-0000-0000-000000000001'),'Schedule lost original timing or device selection');
  if(state==='activated')browser.check(view.links.some(a=>a.text==='Open activation receipt'&&a.href==='/tenant/1/site/1/ios/update-plans/70000000-0000-0000-0000-000000000001/group-assignments/40000000-0000-0000-0000-000000000001'),'Activated schedule lost original receipt');
  if(state==='blocked')browser.check(view.text.includes('new review required')&&view.text.includes('existing device policies changed'),'Blocked schedule lost its reason');
  if(state==='waiting')browser.check(view.text.includes('Next attempt (UTC)')&&view.text.includes('Temporary database contention'),'Waiting schedule lost retry state');
  if(state==='expired')browser.check(view.text.includes('without a committed assignment'),'Expired schedule implies device work');
  if(state==='history')browser.check(view.links.some(a=>a.text==='Older schedules'&&a.href.endsWith('?before=80000000-0000-0000-0000-000000000001')),'Schedule history lost scoped cursor');
  if(state==='empty-history')browser.check(view.text.includes('No scheduled activations')&&!view.links.some(a=>a.text==='Older schedules'),'Empty schedule history offers more results');
  if(width===390)await browser.capture('apple-update-schedule-'+state+'-390');record({name:'Apple update schedule '+state,width,passed:true});
 }
}
