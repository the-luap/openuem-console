export default async function run(browser,record) {
 for(const width of [390,768,1440]) for(const family of ['operations','registrations']) for(const kind of family==='operations'?['resolution-retry','resolution-retry-long']:['resolution-retry-release','resolution-retry-withdraw','resolution-retry-long']) {
  await browser.visit('netbird-'+family+'-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(text.includes('original outcome remains unconfirmed')&&text.includes('Recovery attempts')&&text.includes('Latest attempt ID'),'Recovery hides original uncertainty or permanent attempts');
  browser.check(text.includes(kind==='resolution-retry-withdraw'?'permanently withdraw':'execution that has ended'),'Recovery describes the wrong action');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Recovery has duplicate IDs');
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Recovery page overflows');
  await browser.evaluate(`window.recoveryRequests=[];document.body.addEventListener('htmx:configRequest',e=>{recoveryRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-retry-submit').focus()`);await browser.enter();
  browser.check(await browser.evaluate('recoveryRequests.length===0'),'Recovery submitted without confirmation');
  await browser.evaluate(`document.querySelector('#netbird-retry-confirm').checked=true;document.querySelector('#netbird-retry-submit').focus()`);await browser.enter();
  const req=await browser.evaluate('recoveryRequests.at(-1)');
  const resolutionID=family==='operations'?'10000000-0000-4000-8000-000000000004':'20000000-0000-4000-8000-000000000002';
  browser.check(req?.path==='/tenant/1/site/2/computers/owned-device/netbird/'+family+'/10000000-0000-4000-8000-000000000001/resolution/retry'&&req.fields.length===5&&req.fields.some(([k,v])=>k==='resolution_id'&&v===resolutionID)&&req.fields.some(([k,v])=>k==='retry_id'&&v==='30000000-0000-4000-8000-000000000003')&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Recovery lost exact scope, fresh review or separate attempt identity');
  if(width===390&&kind.endsWith('long')) await browser.capture('netbird-'+family+'-'+kind+'-390');
  record({name:'NetBird '+family+' '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) for(const family of ['operations','registrations']) for(const first of ['retry','check']) {
  await browser.visit('netbird-'+family+(family==='operations'?'-resolution-retry':'-resolution-retry-withdraw'),width);
  const check=family==='operations'?'#netbird-submit':'#netbird-check';
  const button=first==='retry'?'#netbird-retry-submit':check;
  await browser.evaluate(`window.recoverySends=0;XMLHttpRequest.prototype.send=function(){recoverySends++};document.querySelectorAll('input[type=checkbox]').forEach(e=>e.checked=true);document.querySelector('${button}').focus()`);await browser.enter();
  browser.check(await browser.evaluate(`recoverySends===1&&document.querySelector('#netbird-retry-submit').disabled&&document.querySelector('#netbird-retry-confirm').disabled&&document.querySelector('${check}').disabled`),'Pending recovery and evidence check leave another action enabled');
  await browser.evaluate(`document.querySelectorAll('.netbird-confirm').forEach(f=>f.requestSubmit())`);
  browser.check(await browser.evaluate('recoverySends===1'),'Concurrent receipt check repeated a recovery request');
  record({name:'NetBird '+family+' '+first+' excludes concurrent forms',width,passed:true});
 }
}
