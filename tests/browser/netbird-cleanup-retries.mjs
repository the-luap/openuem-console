export default async function run(browser,record) {
 for(const width of [390,768,1440]) for(const kind of ['ready','retry','long','absent','retained','changed','unavailable']) {
  await browser.visit('netbird-registrations-cleanup-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(text.includes('original outcome remains unconfirmed')&&text.includes('commands remain blocked')&&text.includes('does not disconnect a peer'),'Key removal hides original uncertainty or its limits');
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Key removal page overflows');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Key removal has duplicate IDs');
  if(kind!=='ready') browser.check(text.includes('Latest removal attempt ID')&&text.includes('attempt alone does not confirm key absence'),'Key removal hides retained attempts');
  if(['ready','retry','long'].includes(kind)) {
   browser.check(text.includes('one new removal attempt')&&text.includes('original provider'),'Key removal omits the exact authorized effect');
   await browser.evaluate(`window.cleanupRequests=[];document.body.addEventListener('htmx:configRequest',e=>{cleanupRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-cleanup-submit').focus()`);await browser.enter();
   browser.check(await browser.evaluate('cleanupRequests.length===0'),'Key removal submitted without explicit confirmation');
   await browser.evaluate(`document.querySelector('#netbird-cleanup-confirm').checked=true;document.querySelector('#netbird-cleanup-submit').focus()`);await browser.enter();
   const req=await browser.evaluate('cleanupRequests.at(-1)');
   browser.check(req?.path==='/tenant/1/site/2/computers/owned-device/netbird/registrations/10000000-0000-4000-8000-000000000001/cleanup/retry'&&req.fields.length===4&&req.fields.some(([k,v])=>k==='retry_id'&&v==='30000000-0000-4000-8000-000000000003')&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf')&&req.fields.some(([k,v])=>k==='confirmed'&&v==='yes'),'Key removal lost exact target, fresh review, CSRF or separate attempt identity');
  } else {
   browser.check(await browser.evaluate(`document.querySelector('#netbird-cleanup-submit')===null`),'Blocked or absent key permits a retry');
   browser.check(await browser.evaluate(`Boolean(document.querySelector('#netbird-cleanup-check'))`)===(kind==='absent'),'Absence observation is confused with retained proof');
  }
  if(width===390&&kind==='long') await browser.capture('netbird-cleanup-long-390');
  record({name:'NetBird key removal '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) {
  await browser.visit('netbird-registrations-cleanup-retry',width);
  await browser.evaluate(`window.cleanupSends=0;XMLHttpRequest.prototype.send=function(){cleanupSends++};document.querySelector('#netbird-cleanup-confirm').checked=true;document.querySelector('#netbird-cleanup-submit').focus()`);await browser.enter();
  browser.check(await browser.evaluate(`cleanupSends===1&&document.querySelector('#netbird-cleanup-submit').disabled&&document.querySelector('#netbird-cleanup-confirm').disabled`),'Pending key removal leaves its action enabled');
  await browser.evaluate(`document.querySelector('.netbird-confirm').requestSubmit()`);
  browser.check(await browser.evaluate('cleanupSends===1'),'Pending key removal resubmits');
  record({name:'NetBird key removal excludes concurrent submission',width,passed:true});
 }
}
