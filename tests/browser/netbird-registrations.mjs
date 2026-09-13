export default async function run(browser,record) {
 const kinds=['choices','choices-empty','choices-long','review','review-empty','review-long','queued','started','completed','stopped','unconfirmed-create','unconfirmed-delivery','unconfirmed-cleanup','unconfirmed-cleaned','unconfirmed-viewer','history','history-empty','history-full'];
 const base='/tenant/1/site/2/computers/owned-device/netbird/registrations';
 for(const width of [390,768,1440]) for(const kind of kinds) {
  await browser.visit('netbird-registrations-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Registration page has duplicate IDs');
  browser.check(!text.includes('!(MISSING:')&&!text.includes('@netbird')&&!await browser.evaluate(`!!document.querySelector('Berlin')`),'Registration labels became markup or template source');
  if(kind.startsWith('choices')) {
   browser.check(text.includes('does not create a key'),'Group selection hides its read-only effect');
   await browser.evaluate(`window.groupFields=null;document.querySelector('.netbird-registration-choices').addEventListener('submit',e=>{e.preventDefault();groupFields=[...new FormData(e.target)]});document.querySelector('input[name=group]')?.click();document.querySelector('#netbird-extra-dns').click();document.querySelector('.netbird-registration-choices button').focus()`);await browser.enter();
   const fields=await browser.evaluate('groupFields');
   browser.check(fields?.some(([k,v])=>k==='extra_dns'&&v==='yes'),'Group selection lost DNS choice');
   const groups=fields.filter(([k])=>k==='group');
   browser.check(kind==='choices-empty'?groups.length===0:groups.length===1&&groups[0][1]===(kind==='choices-long'?'g'.repeat(128):'owned-group'),'Group selection submitted a label instead of its exact ID');
  } else if(kind.startsWith('review')) {
   browser.check(text.includes('interrupt access')&&text.includes('existing registration may retain')&&text.includes('key removal alone does not release'),'Registration review omitted impact or uncertainty');
   await browser.evaluate(`window.registrationRequests=[];document.body.addEventListener('htmx:configRequest',e=>{registrationRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-submit').focus()`);await browser.enter();
   browser.check(await browser.evaluate('registrationRequests.length===0'),'Registration submitted without confirmation');
   await browser.evaluate(`document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
   const req=await browser.evaluate('registrationRequests.at(-1)');
   browser.check(req?.path===base&&req.fields.length===(kind==='review-empty'?5:6)&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf')&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='extra_dns'&&v===(kind==='review-empty'?'no':'yes')),'Registration confirmation lost reviewed policy, identity or CSRF');
   if(kind!=='review-empty') browser.check(req.fields.some(([k,v])=>k==='group'&&v===(kind==='review-long'?'g'.repeat(128):'owned-group')),'Registration posted the wrong provider group');
  } else if(kind==='queued') {
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-cancel[required]')`),'Unattempted registration cannot be explicitly cancelled');
  } else if(kind==='started') {
   browser.check(!await browser.evaluate(`!!document.querySelector('#netbird-cancel')`),'Started registration offers an unsafe cancellation');
  } else if(kind.startsWith('unconfirmed')) {
   browser.check(text.includes('Registration is unconfirmed')&&!text.includes('Command execution and setup-key removal confirmed'),'Registration uncertainty was upgraded to success');
   const canCheck=kind==='unconfirmed-cleanup';
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-cleanup')`)===canCheck,'Registration offered an ineligible cleanup action');
   if(canCheck) {
    await browser.evaluate(`window.cleanupRequest=null;document.body.addEventListener('htmx:configRequest',e=>{cleanupRequest={path:e.detail.path,fields:[...e.detail.formData.entries()]};e.preventDefault()});document.querySelector('#netbird-cleanup').focus()`);await browser.enter();
    const req=await browser.evaluate('cleanupRequest');
    browser.check(req?.path===base+'/10000000-0000-4000-8000-000000000001/cleanup'&&req.fields.length===2&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Cleanup check lost scope or CSRF');
   }
  } else if(kind==='history-full') {
   browser.check(await browser.evaluate(`document.querySelector('a[href*="?before="]').getAttribute('href')`)===base+'?before=10000000-0000-4000-8000-000000000050','Registration history cursor skipped its last record');
  }
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Registration page overflows the viewport');
  if(width===390&&['choices-long','review-long','unconfirmed-cleanup'].includes(kind))await browser.capture('netbird-registrations-'+kind+'-390');
  record({name:'NetBird registration '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) {
  await browser.visit('netbird-registrations-review',width);
  await browser.evaluate(`window.registrationXHR=null;window.registrationSends=0;window.registrationOriginal=document.querySelector('#main').outerHTML;XMLHttpRequest.prototype.send=function(){registrationXHR=this;registrationSends++};document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
  browser.check(await browser.evaluate(`registrationSends===1&&document.querySelector('#netbird-submit').disabled&&document.querySelector('#netbird-confirm').disabled&&document.querySelector('#netbird-pending').getBoundingClientRect().height>0`),'Pending registration lacks a visible state or allows repeated input');
  await browser.evaluate(`document.querySelector('.netbird-confirm').requestSubmit()`);
  browser.check(await browser.evaluate('registrationSends===1'),'Registration was submitted twice while pending');
  await browser.evaluate(`(()=>{const xhr=registrationXHR;Object.defineProperties(xhr,{status:{value:200},response:{value:registrationOriginal},responseText:{value:registrationOriginal},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
  await browser.evaluate('new Promise(resolve=>setTimeout(resolve,50))');
  browser.check(await browser.evaluate(`document.querySelectorAll('#main').length===1&&document.activeElement.id==='netbird-operation-heading'`),'Registration response lost page focus');
  record({name:'NetBird registration pending and focus',width,passed:true});
 }
}
