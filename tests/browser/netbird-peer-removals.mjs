export default async function run(browser,record) {
 const path='/tenant/1/site/2/computers/owned-device/netbird/registrations/10000000-0000-4000-8000-000000000001/peer/removal';
 for(const width of [390,768,1440]) for(const kind of ['present','retry','long','absent','retained','changed','unavailable','unassociated','receipt','receipt-viewer']) {
  await browser.visit('netbird-registrations-removal-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Peer removal page overflows');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Peer removal has duplicate IDs');
  if(kind!=='unassociated') browser.check(text.includes('Retained provider peer')&&text.includes('Original provider')&&text.includes('Provider registration event'),'Removal hides its exact association');
  if(kind==='retained'||kind.startsWith('receipt')) {
   browser.check(text.includes('Confirmed by an exact-ID provider read')&&text.includes('does not uninstall NetBird')&&text.includes('does not change the original registration outcome'),'Absence receipt overstates the result');
   if(kind.startsWith('receipt')) browser.check(await browser.evaluate(`Boolean(document.querySelector('#netbird-peer-removal-link'))`)===(kind==='receipt'),'Removal management access differs from reader authority');
  }else browser.check(text.includes('commands remain blocked'),'Removal hides original uncertainty');
  if(kind==='present'||kind==='retry'||kind==='long') {
   browser.check(text.includes('one removal attempt')&&text.includes('interrupt its network access')&&text.includes('no device command is sent'),'Removal confirmation hides its effect');
   await browser.evaluate(`window.removalForms=[];document.body.addEventListener('htmx:configRequest',e=>{removalForms.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-peer-removal-submit').focus()`);await browser.enter();
   browser.check(await browser.evaluate('removalForms.length===0'),'Removal submitted without confirmation');
   await browser.evaluate(`document.querySelector('#netbird-peer-removal-confirm').checked=true;document.querySelector('#netbird-peer-removal-submit').focus()`);await browser.enter();
   const req=await browser.evaluate('removalForms.at(-1)');
   browser.check(req?.path===path&&req.fields.length===4&&req.fields.some(([k,v])=>k==='removal_id'&&v==='30000000-0000-4000-8000-000000000003')&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='confirmed'&&v==='yes')&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Removal loses exact scope, attempt, review or CSRF');
  }else browser.check(await browser.evaluate(`document.querySelector('#netbird-peer-removal-submit')===null`),'Blocked state allows deletion');
  if(!['retained','unassociated','receipt','receipt-viewer'].includes(kind)) {
   browser.check(text.includes('never repeats a removal attempt'),'Check does not describe read-only semantics');
   await browser.evaluate(`window.checkForms=[];document.body.addEventListener('htmx:configRequest',e=>{checkForms.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-peer-removal-check').focus()`);await browser.enter();
   const req=await browser.evaluate('checkForms.at(-1)');
   browser.check(req?.path===path+'/check'&&req.fields.length===2&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf')&&req.fields.some(([k,v])=>k==='confirmed'&&v==='yes'),'Read-only check loses scope or CSRF');
  }
  if(width===390&&kind==='long') await browser.capture('netbird-peer-removal-long-390');
  record({name:'NetBird peer removal '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) for(const mode of ['remove','check']) {
  await browser.visit('netbird-registrations-removal-present',width);
  const button=mode==='remove'?'#netbird-peer-removal-submit':'#netbird-peer-removal-check';
  await browser.evaluate(`window.removalSends=0;XMLHttpRequest.prototype.send=function(){removalSends++};document.querySelector('#netbird-peer-removal-confirm').checked=true;document.querySelector(${JSON.stringify(button)}).focus()`);await browser.enter();
  browser.check(await browser.evaluate(`removalSends===1&&document.querySelector(${JSON.stringify(button)}).disabled`),'Pending peer action permits duplicate submission');
  if(mode==='remove') browser.check(await browser.evaluate(`document.querySelector('#netbird-peer-removal-confirm').disabled`),'Pending removal leaves confirmation enabled');
  await browser.evaluate(`document.querySelector(${JSON.stringify(button)}).closest('form').requestSubmit()`);
  browser.check(await browser.evaluate('removalSends===1'),'Pending peer action submits again');
  record({name:'NetBird peer '+mode+' excludes duplicate submission',width,passed:true});
 }
}
