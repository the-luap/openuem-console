export default async function run(browser,record) {
 const kinds=['choices','choices-empty','choices-long','review','review-empty','review-long','queued','started','completed','stopped','unconfirmed-create','unconfirmed-delivery','unconfirmed-cleanup','unconfirmed-cleaned','unconfirmed-viewer','history','history-empty','history-full','unconfirmed-resolved','history-resolved','resolution-completed','resolution-release','resolution-cleanup','resolution-no-delivery','resolution-continue','resolution-pending','resolution-confirmed','resolution-unknown-key','resolution-missing-receipt','resolution-active','resolution-changed-key','resolution-unavailable','resolution-long'];
 const base='/tenant/1/site/2/computers/owned-device/netbird/registrations';
 for(const width of [390,768,1440]) for(const kind of kinds) {
  await browser.visit('netbird-registrations-'+kind,width);
  const text=await browser.evaluate('document.body.innerText');
  browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Registration page has duplicate IDs');
  browser.check(!text.includes('!(MISSING:')&&!text.includes('@netbird')&&!await browser.evaluate(`!!document.querySelector('Berlin')`),'Registration labels became markup or template source');
  if(kind.startsWith('resolution-')) {
   browser.check(text.includes('original outcome remains unconfirmed')&&text.includes('Setup key')&&text.includes('Agent evidence'),'Resolution hides separate evidence or changes the original outcome');
   const actionable=['resolution-completed','resolution-release','resolution-cleanup','resolution-no-delivery','resolution-continue','resolution-long'].includes(kind);
   const checking=['resolution-continue','resolution-pending','resolution-long'].includes(kind);
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-confirm')`)===actionable,'Resolution offers an ineligible confirmation');
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-check')`)===checking,'Resolution offers an ineligible evidence check');
   await browser.evaluate(`window.resolutionRequests=[];document.body.addEventListener('htmx:configRequest',e=>{resolutionRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()})`);
   if(actionable) {
    await browser.evaluate(`document.querySelector('#netbird-submit').focus()`);await browser.enter();
    browser.check(await browser.evaluate('resolutionRequests.length===0'),'Resolution submitted without explicit confirmation');
    await browser.evaluate(`document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
    const req=await browser.evaluate('resolutionRequests.at(-1)');
    const continuing=['resolution-continue','resolution-long'].includes(kind);
    browser.check(req?.path===base+'/10000000-0000-4000-8000-000000000001/resolution'+(continuing?'/continue':'')&&req.fields.length===4&&req.fields.some(([k,v])=>k==='resolution_id'&&v===(continuing?'20000000-0000-4000-8000-000000000002':'30000000-0000-4000-8000-000000000003'))&&req.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Resolution lost its scope, reviewed revision, retained identity or CSRF');
   }
   if(checking) {
    browser.check(text.includes('cannot repeat key removal or send an agent release'),'Evidence check misstates its effects');
    await browser.evaluate(`document.querySelector('#netbird-check').focus()`);await browser.enter();
    const req=await browser.evaluate('resolutionRequests.at(-1)');
    browser.check(req?.path===base+'/10000000-0000-4000-8000-000000000001/resolution/reconcile'&&req.fields.length===3&&req.fields.some(([k,v])=>k==='resolution_id'&&v==='20000000-0000-4000-8000-000000000002')&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Evidence check lost retained identity or CSRF');
   }
   if(kind==='resolution-confirmed') browser.check(!await browser.evaluate(`!!document.querySelector('.netbird-operations form')`)&&text.includes('Further NetBird commands may be reviewed'),'Confirmed resolution offers another mutation');
   if(kind==='resolution-cleanup') browser.check(text.includes('only after the provider confirms key absence'),'Resolution permits release before key removal');
   if(kind==='resolution-no-delivery') browser.check(text.includes('without contacting the agent'),'Undelivered resolution invents agent evidence');
  } else if(kind.startsWith('choices')) {
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
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-resolution-link')`)===(kind!=='unconfirmed-viewer'),'Registration resolution link ignores management authority');
   if(kind==='unconfirmed-resolved') browser.check(text.includes('Resolution confirmed.')&&text.includes('Further NetBird commands may be reviewed')&&!text.includes('commands remain blocked'),'Resolved receipt retains a false block');
   const canCheck=kind==='unconfirmed-cleanup';
   browser.check(await browser.evaluate(`!!document.querySelector('#netbird-cleanup')`)===canCheck,'Registration offered an ineligible cleanup action');
   if(canCheck) {
    await browser.evaluate(`window.cleanupRequest=null;document.body.addEventListener('htmx:configRequest',e=>{cleanupRequest={path:e.detail.path,fields:[...e.detail.formData.entries()]};e.preventDefault()});document.querySelector('#netbird-cleanup').focus()`);await browser.enter();
    const req=await browser.evaluate('cleanupRequest');
    browser.check(req?.path===base+'/10000000-0000-4000-8000-000000000001/cleanup'&&req.fields.length===2&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Cleanup check lost scope or CSRF');
   }
  } else if(kind==='history-resolved') {
   browser.check(text.includes('unconfirmed · resolution confirmed'),'History overwrites the original uncertain result');
  } else if(kind==='history-full') {
   browser.check(await browser.evaluate(`document.querySelector('a[href*="?before="]').getAttribute('href')`)===base+'?before=10000000-0000-4000-8000-000000000050','Registration history cursor skipped its last record');
  }
  browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Registration page overflows the viewport');
  if(width===390&&['choices-long','review-long','unconfirmed-cleanup','resolution-long','resolution-continue'].includes(kind))await browser.capture('netbird-registrations-'+kind+'-390');
  record({name:'NetBird registration '+kind,width,passed:true});
 }
 for(const width of [390,768,1440]) for(const pendingKind of ['review','resolution-continue']) {
  await browser.visit('netbird-registrations-'+pendingKind,width);
  await browser.evaluate(`window.registrationXHR=null;window.registrationSends=0;window.registrationOriginal=document.querySelector('#main').outerHTML;XMLHttpRequest.prototype.send=function(){registrationXHR=this;registrationSends++};document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
  browser.check(await browser.evaluate(`registrationSends===1&&document.querySelector('#netbird-submit').disabled&&document.querySelector('#netbird-confirm').disabled&&document.querySelector('#netbird-pending').getBoundingClientRect().height>0`),'Pending registration lacks a visible state or allows repeated input');
  if(pendingKind==='resolution-continue') {
   browser.check(await browser.evaluate(`document.querySelector('#netbird-check').disabled`),'Pending continuation leaves evidence check enabled');
   await browser.evaluate(`document.querySelector('#netbird-check').form.requestSubmit()`);
  }
  await browser.evaluate(`document.querySelector('.netbird-confirm').requestSubmit()`);
  browser.check(await browser.evaluate('registrationSends===1'),'Registration was submitted twice while pending');
  await browser.evaluate(`(()=>{const xhr=registrationXHR;Object.defineProperties(xhr,{status:{value:200},response:{value:registrationOriginal},responseText:{value:registrationOriginal},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
  await browser.evaluate('new Promise(resolve=>setTimeout(resolve,50))');
  browser.check(await browser.evaluate(`document.querySelectorAll('#main').length===1&&document.activeElement.id==='netbird-operation-heading'`),'Registration response lost page focus');
  if(pendingKind==='resolution-continue') browser.check(await browser.evaluate('registrationSends===1'),'Concurrent evidence check repeated a pending request');
  record({name:'NetBird registration '+pendingKind+' pending and focus',width,passed:true});
 }
}
