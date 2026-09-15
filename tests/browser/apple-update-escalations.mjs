export default async function run(browser,record) {
 for(const state of ['new','watching','attention','awaiting','acknowledged','paused','blocked-authority','blocked-source','viewer','history','event-configured','event-acknowledged','event-cleared','event-attention','event-blocked','list','empty','long'])for(const width of [390,768,1440]) {
  await browser.visit('apple-update-escalation-'+state,width);
  const view=await browser.evaluate(`(()=>{const m=document.querySelector('[data-update-escalation-page]');return {width:document.documentElement.scrollWidth,viewport:innerWidth,page:m.dataset.updateEscalationPage,text:m.textContent,scripts:m.querySelectorAll('script').length,forms:[...m.querySelectorAll('form')].map(f=>({kind:f.dataset.escalationAction,key:f.elements.request_key.value,revision:f.elements.configuration_revision.value,csrf:f.elements.csrf.value,action:f.getAttribute('action'),confirm:f.elements.confirmed.required,enabled:f.elements.enabled?.value,incident:f.elements.incident?.value})),links:[...m.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))}})()`);
  browser.check(view.width<=view.viewport+1&&view.scripts===0,'Escalation page overflows or renders executable source markup');
  const editable=['new','watching','attention','awaiting','acknowledged','paused','blocked-authority','blocked-source','long'].includes(state);
  const ack=['attention','awaiting','paused','blocked-authority','blocked-source','long'].includes(state);
  browser.check(view.forms.length===(editable?(ack?2:1):0),'Escalation form availability changed');
  browser.check(view.forms.every(f=>f.confirm&&f.csrf==='owned-csrf'&&f.revision===(state==='new'?'0':'1')&&f.action==='/tenant/1/site/1/ios/update-plans/30000000-0000-4000-8000-000000000001/group-assignments/40000000-0000-4000-8000-000000000001/escalation'+(f.kind==='acknowledge'?'/acknowledge':'')),'Monitoring form lost source scope, configuration or confirmation');
  browser.check(new Set(view.forms.map(f=>f.key)).size===view.forms.length,'Different monitoring actions share a request key');
  if(editable)browser.check(view.forms[0].enabled===(['new','paused','blocked-authority','blocked-source'].includes(state)?'yes':'no'),'Monitoring action has the wrong enabled intent');
  if(ack)browser.check(view.forms[1].incident==='60000000-0000-4000-8000-000000000001','Acknowledgment lost original episode');
  if(view.page==='review')browser.check(view.text.includes('does not send email or device commands')&&view.text.includes('does not change the saved incident')&&view.text.includes('Unknown evidence keeps an existing incident open'),'Review hides monitoring channel or evidence boundaries');
  if(state==='watching')browser.check(view.text.includes('first monitoring check has not completed'),'Unassessed watch invents a result');
  if(state==='awaiting')browser.check(view.text.includes('Awaiting verified evidence: 1')&&view.text.includes('Evidence unverified'),'Unknown evidence clears the open incident');
  if(state==='acknowledged')browser.check(view.text.includes('An operator acknowledged this incident')&&view.forms.length===1,'Acknowledged episode can be acknowledged again');
  if(state==='paused')browser.check(view.text.includes('Monitoring paused')&&view.text.includes('Saved incidents remain visible'),'Pause silently resolves incident');
  if(state==='blocked-authority')browser.check(view.text.includes('permissions or scope changed'),'Authority block is not explained');
  if(state==='blocked-source')browser.check(view.text.includes('saved evidence could not be verified'),'Source block is not explained');
  if(view.page==='event')browser.check(view.text.includes('unchanged by later monitoring checks')&&view.forms.length===0,'Immutable event exposes mutable intent');
  if(state==='event-cleared')browser.check(view.text.includes('approved update exception is active')&&view.text.includes('does not itself establish OS installation'),'Cleared incident falsely claims installation');
  if(state==='history')browser.check(view.links.some(a=>a.text==='Older events'&&a.href.endsWith('?before=50000000-0000-4000-8000-000000000001')),'History lost authenticated cursor');
  if(state==='list')browser.check(view.links.some(a=>a.text==='Older monitors'&&a.href.endsWith('?before=20000000-0000-4000-8000-000000000001')),'Monitor list lost cursor');
  if(state==='empty')browser.check(view.text.includes('No update monitors are recorded')&&!view.links.some(a=>a.text==='Older monitors'),'Empty list invented monitor');
  if(view.forms.length) {
   await browser.evaluate(`(()=>{window.escalationSubmissions=[];for(const f of document.querySelectorAll('[data-update-escalation-page] form')){f.addEventListener('submit',e=>{e.preventDefault();window.escalationSubmissions.push(Object.fromEntries(new FormData(f,e.submitter)))});if(f.elements.reason)f.elements.reason.value='Owned keyboard incident follow-up';}})()`);
   for(let i=0;i<view.forms.length;i++) {
    await browser.evaluate(`document.querySelectorAll('[data-update-escalation-page] form')[${i}].querySelector('button[type="submit"]').focus()`);await browser.enter();
    browser.check(await browser.evaluate('window.escalationSubmissions.length')===i,'Unconfirmed monitoring action submitted');
    await browser.evaluate(`document.querySelectorAll('[data-update-escalation-page] form')[${i}].elements.confirmed.focus()`);await browser.space();
    await browser.evaluate(`document.querySelectorAll('[data-update-escalation-page] form')[${i}].querySelector('button[type="submit"]').focus()`);await browser.enter();
   }
   const submitted=await browser.evaluate('window.escalationSubmissions');
   browser.check(submitted.length===view.forms.length&&submitted.every((s,i)=>s.confirmed==='yes'&&s.request_key===view.forms[i].key&&s.configuration_revision===view.forms[i].revision),'Confirmed monitoring form lost reviewed intent');
  }
  if(width===390){await browser.evaluate("document.querySelector('[data-update-escalation-page]').scrollIntoView({block:'start'})");await browser.capture('apple-update-escalation-'+state+'-390');}
  record({name:'Apple update escalation '+state,width,passed:true});
 }
}
