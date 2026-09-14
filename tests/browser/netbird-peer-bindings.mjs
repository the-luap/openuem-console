export default async function run(browser,record) {
 for(const width of [390,768,1440]) for(const kind of ['matched','long','retained','missing','unavailable','conflict','absent','cleanup-required','key-unknown','not-delivered','receipt','receipt-viewer']) {
  await browser.visit('netbird-registrations-peer-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Peer association page overflows');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Peer association has duplicate IDs');
  if(kind==='retained'||kind.startsWith('receipt')) {
   browser.check(text.includes('Retained provider peer')&&text.includes('Association ID')&&text.includes('Provider registration event')&&text.includes('does not establish current local WireGuard identity'),'Retained association hides its evidence or limits');
   if(kind.startsWith('receipt')) browser.check(await browser.evaluate(`Boolean(document.querySelector('#netbird-peer-review-link'))`)===(kind==='receipt'),'Receipt exposes management to a reader or hides its review');
  } else {
   browser.check(text.includes('Names and IP addresses are not identity evidence')&&text.includes('cannot prove that no registration occurred')&&text.includes('commands remain blocked'),'Peer association hides missing evidence or changes original uncertainty');
  }
  if(kind==='matched'||kind==='long') {
   browser.check(text.includes('does not delete or modify a peer')&&text.includes('permanently records'),'Association describes the wrong authorized effect');
   await browser.evaluate(`window.peerForms=[];document.body.addEventListener('htmx:configRequest',e=>{peerForms.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-peer-submit').focus()`);await browser.enter();
   browser.check(await browser.evaluate('peerForms.length===0'),'Association submitted without confirmation');
   await browser.evaluate(`document.querySelector('#netbird-peer-confirm').checked=true;document.querySelector('#netbird-peer-submit').focus()`);await browser.enter();
   const req=await browser.evaluate('peerForms.at(-1)');
   browser.check(req?.path==='/tenant/1/site/2/computers/owned-device/netbird/registrations/10000000-0000-4000-8000-000000000001/peer'&&req.fields.length===4&&req.fields.some(([k,v])=>k==='binding_id'&&v==='30000000-0000-4000-8000-000000000003')&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='confirmed'&&v==='yes')&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Association lost exact scope, fresh evidence, identity or CSRF');
  } else browser.check(await browser.evaluate(`document.querySelector('#netbird-peer-submit')===null`),'Insufficient or retained evidence permits another association');
  if(width===390&&kind==='long') await browser.capture('netbird-peer-long-390');
  record({name:'NetBird provider peer '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) {
  await browser.visit('netbird-registrations-peer-matched',width);
  await browser.evaluate(`window.peerSends=0;XMLHttpRequest.prototype.send=function(){peerSends++};document.querySelector('#netbird-peer-confirm').checked=true;document.querySelector('#netbird-peer-submit').focus()`);await browser.enter();
  browser.check(await browser.evaluate(`peerSends===1&&document.querySelector('#netbird-peer-confirm').disabled&&document.querySelector('#netbird-peer-submit').disabled`),'Pending association leaves another submission enabled');
  await browser.evaluate(`document.querySelector('.netbird-confirm').requestSubmit()`);
  browser.check(await browser.evaluate('peerSends===1'),'Pending association repeats submission');
  record({name:'NetBird peer association excludes duplicate submission',width,passed:true});
 }
}
