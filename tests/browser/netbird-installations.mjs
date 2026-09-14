const kinds=['choices','choices-empty','choices-long','review','review-long','queued','preparation-pending','prepared','delivery-pending','unconfirmed','viewer','stopped','cancelled','completed','released','history','history-empty','history-full','resolution-withdraw','resolution-release','resolution-retry','resolution-waiting','resolution-conflict','resolution-confirm','resolution-completed','resolution-released','resolution-long'];
const base='/tenant/1/site/2/computers/90000000-0000-4000-8000-000000000009/netbird/installations';
const id='10000000-0000-4000-8000-000000000001';
const confirmationKinds=['review','review-long','resolution-withdraw','resolution-release','resolution-retry','resolution-long'];
export default async function netbirdInstallations(browser,record){
 for(const width of [390,768,1440]){
  for(const kind of kinds){
   await browser.visit('netbird-installations-'+kind,width);
   browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Installation layout overflows at '+kind);
   browser.check(await browser.evaluate(`document.querySelectorAll('#netbird-operation-heading').length===1&&!document.querySelector('native')&&!document.querySelector('operator')`),'Installation metadata became markup');
   if(kind==='viewer'||['cancelled','completed','released'].includes(kind))browser.check(!await browser.evaluate(`!!document.querySelector('.netbird-operations form')`),'Historical/reader receipt exposes an action');
   if(kind==='choices-empty')browser.check(await browser.evaluate(`document.body.textContent.includes('No matching approved packages')&&!document.querySelector('.netbird-operations button')`),'Empty choices offer an installation');
   if(kind==='choices'||kind==='choices-long'){
    await browser.evaluate(`window.chosen=null;document.querySelector('.netbird-installation-choice').addEventListener('submit',e=>{e.preventDefault();chosen={action:e.target.getAttribute('action'),fields:[...new FormData(e.target)]}});document.querySelector('.netbird-installation-choice button').focus()`);
    await browser.enter();
    const result=await browser.evaluate('chosen');const f=Object.fromEntries(result.fields);
    browser.check(result.action===base+'/review'&&f.approval_id==='30000000-0000-4000-8000-000000000003'&&f.approval_digest==='b'.repeat(64)&&result.fields.length===2,'Package choice lost exact approval or scope');
   }
   if(kind==='history-full')browser.check(await browser.evaluate(`document.querySelectorAll('.netbird-history li').length===20&&[...document.querySelectorAll('a')].some(a=>a.getAttribute('href')==='${base}?before=${id}')`),'History loses scoped pagination');
   if(['delivery-pending','unconfirmed'].includes(kind))browser.check(await browser.evaluate(`!document.querySelector('form[action$="/cancel"]')&&!!document.querySelector('form[action$="/observe"]')`),'Native receipt permits cancellation or loses read-only observation');
   if(['resolution-waiting','resolution-conflict','resolution-completed','resolution-released','resolution-confirm'].includes(kind))browser.check(!await browser.evaluate(`!!document.querySelector('#netbird-submit')`),'Ineligible recovery offers a mutation');
   if(confirmationKinds.includes(kind)){
    await browser.evaluate(`window.installRequest=null;document.body.addEventListener('htmx:configRequest',e=>{installRequest={path:e.detail.path,fields:[...e.detail.formData.entries()]};e.preventDefault()});document.querySelector('#netbird-submit').focus()`);
    await browser.enter();browser.check(await browser.evaluate('installRequest===null'),'Installation/recovery submitted without confirmation');
    await browser.evaluate(`document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
    const result=await browser.evaluate('installRequest');const f=result&&Object.fromEntries(result.fields);
    browser.check(f?.csrf==='owned-netbird-csrf'&&f.confirmed==='yes'&&f.revision==='c'.repeat(64),'Installation form lost CSRF, confirmation or original review');
    if(kind.startsWith('review'))browser.check(result.path===base&&f.request_id===id&&f.approval_id==='30000000-0000-4000-8000-000000000003'&&f.approval_digest==='b'.repeat(64)&&result.fields.length===6,'Installation request lost exact package/review/UUID');
    else browser.check(result.path===base+'/'+id+'/resolution'&&f.resolution_id==='20000000-0000-4000-8000-000000000002'&&f.review_revision==='d'.repeat(64)&&result.fields.length===5,'Recovery lost permanent resolution or expiring review');
   }
   if(['queued','prepared','stopped'].includes(kind)){
    await browser.evaluate(`window.cancelRequest=null;document.querySelector('form[action$="/cancel"]').addEventListener('submit',e=>{e.preventDefault();cancelRequest=[...new FormData(e.target)]});document.querySelector('form[action$="/cancel"] button').focus()`);
    await browser.enter();browser.check(await browser.evaluate('cancelRequest===null'),'Cancellation submitted without confirmation');
    await browser.evaluate(`document.querySelector('#netbird-cancel').checked=true;document.querySelector('form[action$="/cancel"] button').focus()`);await browser.enter();
    const f=Object.fromEntries(await browser.evaluate('cancelRequest'));browser.check(f.csrf==='owned-netbird-csrf'&&f.revision==='c'.repeat(64)&&f.cancellation_id==='50000000-0000-4000-8000-000000000005','Cancellation lost original request intent');
   }
   if(width===390&&['choices-long','review-long','released','resolution-long'].includes(kind))await browser.capture('netbird-installations-'+kind+'-390');
   record({name:'NetBird installations '+kind,width,passed:true});
  }
  for(const kind of ['review','resolution-withdraw','resolution-release']){
   await browser.visit('netbird-installations-'+kind,width);
   await browser.evaluate(`window.installXHR=null;window.installSends=0;XMLHttpRequest.prototype.send=function(){installXHR=this;installSends++};document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
   browser.check(await browser.evaluate(`installSends===1&&document.querySelector('#netbird-submit').disabled&&document.querySelector('#netbird-confirm').disabled&&getComputedStyle(document.querySelector('#netbird-pending')).display!=='none'`),'Pending installation action lacks progress or leaves controls active');
   await browser.evaluate(`document.querySelector('#netbird-submit').form.requestSubmit()`);browser.check(await browser.evaluate('installSends===1'),'Pending installation action was sent twice');
   await browser.evaluate(`(()=>{const xhr=installXHR;Object.defineProperties(xhr,{status:{value:204},response:{value:''},responseText:{value:''},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
   browser.check(await browser.evaluate(`!document.querySelector('#netbird-submit').disabled`),'Installation controls did not recover after response');
   record({name:'NetBird installations '+kind+' pending',width,passed:true});
  }
 }
}
