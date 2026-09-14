export default async function run(browser,record) {
 const kinds=['resolution-withdraw','resolution-withdraw-long','resolution-withdraw-pending','resolution-withdrawn','resolution-withdraw-completed','resolution-retry-withdraw','resolution-withdraw-retry-release','resolution-recovery-unavailable','resolution-withdraw-waiting','resolution-full'];
 const base='/tenant/1/site/2/computers/owned-device/netbird/operations/10000000-0000-4000-8000-000000000001/resolution';
 for(const width of [390,768,1440]) for(const kind of kinds) {
  await browser.visit('netbird-operations-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(text.includes('original outcome remains unconfirmed'),'Withdrawal hides original uncertainty');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Withdrawal has duplicate IDs');
  const initial=['resolution-withdraw','resolution-withdraw-long'].includes(kind);
  const retry=['resolution-retry-withdraw','resolution-withdraw-retry-release'].includes(kind);
  const checking=!initial&&!['resolution-recovery-unavailable','resolution-full'].includes(kind);
  browser.check(await browser.evaluate(`!!document.querySelector('#netbird-submit')`)===(initial||checking),'Withdrawal offers an ineligible confirmation');
  browser.check(await browser.evaluate(`!!document.querySelector('#netbird-retry-submit')`)===retry,'Withdrawal offers an ineligible recovery attempt');
  if(initial) browser.check(text.includes('permanently withdraws')&&text.includes('rejects any later delivery')&&text.includes('Existing execution attempts cannot be withdrawn'),'Withdrawal omits its permanent effect or execution boundary');
  if(kind==='resolution-withdrawn') browser.check(text.includes('matching permanent withdrawal'),'Retained withdrawal proof is not explained');
  if(kind==='resolution-withdraw-completed') browser.check(text.includes('Execution completed before withdrawal'),'Completed execution was presented as withdrawal');
  if(kind==='resolution-recovery-unavailable') browser.check(text.includes('cannot confirm support for permanent withdrawal'),'Older agent is presented as recovery capable');
  if(kind==='resolution-full') browser.check(text.includes('no remaining capacity'),'Full journal lacks an explanation');
  if(kind==='resolution-withdraw-waiting') browser.check(text.includes('cannot yet establish'),'Active execution is hidden');
  await browser.evaluate(`window.withdrawalRequests=[];document.body.addEventListener('htmx:configRequest',e=>{withdrawalRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()})`);
  for(const which of [...(retry?['retry']:[]),...(initial||checking?['main']:[])]) {
   const button=which==='retry'?'#netbird-retry-submit':'#netbird-submit';
   const checkbox=which==='retry'?'#netbird-retry-confirm':'#netbird-confirm';
   const before=await browser.evaluate('withdrawalRequests.length');
   await browser.evaluate(`document.querySelector('${button}').focus()`);await browser.enter();
   browser.check(await browser.evaluate('withdrawalRequests.length')===before,'Withdrawal action submitted without confirmation');
   await browser.evaluate(`document.querySelector('${checkbox}').checked=true;document.querySelector('${button}').focus()`);await browser.enter();
   const req=await browser.evaluate('withdrawalRequests.at(-1)');
   const suffix=which==='retry'?'/retry':initial?'':'/reconcile';
   browser.check(req?.path===base+suffix&&req.fields.length===(which==='retry'?5:initial?4:3)&&req.fields.some(([k,v])=>k==='resolution_id'&&v==='10000000-0000-4000-8000-000000000004')&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Withdrawal lost original request, retained resolution ID or CSRF');
   if(which==='retry') browser.check(req.fields.some(([k,v])=>k==='retry_id'&&v==='30000000-0000-4000-8000-000000000003'),'Recovery lost its separate attempt identity');
   if(which==='retry'||initial) browser.check(req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64)),'Withdrawal lost its fresh review');
  }
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Withdrawal page overflows');
  if(width===390&&['resolution-withdraw-long','resolution-withdraw-completed','resolution-retry-withdraw'].includes(kind))await browser.capture('netbird-operations-'+kind+'-390');
  record({name:'NetBird connection '+kind,width,passed:true});
 }
}
