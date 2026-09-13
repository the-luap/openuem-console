export default async function run(browser, record) {
  const kinds=['choices-task','choices-profile','choices-empty','choices-pending','choices-long','review-task','review-profile','review-long','queued','sending','accepted','rejected','stopped','unconfirmed'];
  const base='/tenant/1/site/2/computers/owned-endpoint/execution';
  for(const width of [390,768,1440])for(const kind of kinds) {
    await browser.visit('manual-execution-'+kind,width);
    const text=await browser.evaluate('document.body.innerText');
    browser.check(!text.includes('!(MISSING:')&&!text.includes('manual_execution.')&&!text.includes('@manual'),'Manual execution contains untranslated or unrendered content');
    browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'Manual execution has duplicate IDs');
    await browser.evaluate(`window.manualRequests=[];document.body.addEventListener('htmx:configRequest',e=>{manualRequests.push({method:e.detail.verb,path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()})`);
    if(kind.startsWith('choices')) {
      browser.check(await browser.evaluate(`document.querySelector('#manual-kind').tagName==='SELECT'&&document.querySelector('#manual-search').maxLength===256`),'Source search does not use bounded native controls');
      if(kind==='choices-pending')browser.check(text.includes('A request is already pending')&&text.includes('Delivery started; outcome pending')&&!await browser.evaluate("!!document.querySelector('#manual-source')"),'Pending request has no receipt or permits another selection');
      else if(kind==='choices-empty')browser.check(text.includes('No compatible sources')&&!await browser.evaluate(`!!document.querySelector('#manual-source')`),'Empty choices offer an unusable action');
      else {
        await browser.evaluate(`document.querySelector('.manual-select button').focus()`);await browser.enter();
        browser.check(await browser.evaluate('manualRequests.length===0'),'Empty source bypassed native validation');
        await browser.evaluate(`document.querySelector('#manual-source').selectedIndex=1;document.querySelector('.manual-select button').focus()`);await browser.enter();
        const request=await browser.evaluate('manualRequests.at(-1)');
        browser.check(request.method==='get'&&request.path===base+'/review'&&request.fields.some(([k,v])=>k==='source_id'&&v===(kind==='choices-profile'?'7':'17')),'Review selection used a display name or another destination');
      }
      await browser.evaluate(`document.querySelector('#manual-search').value='Owned %_';document.querySelector('.manual-search button').focus()`);await browser.enter();
      const search=await browser.evaluate('manualRequests.at(-1)');
      browser.check(search.method==='get'&&search.path===base&&search.fields.some(([k,v])=>k==='q'&&v==='Owned %_'),'Literal source search changed its input or endpoint');
    } else if(kind.startsWith('review')) {
      browser.check(text.includes("agent's system privileges")&&text.includes('at most once'),'Review omitted target impact or delivery uncertainty');
      browser.check(text.includes('Owned <endpoint>')&&text.includes('owned-endpoint'),'Review omitted the concrete target');
      browser.check((kind==='review-profile')===text.includes('does not freeze the profile'),'Profile review hides its current-configuration semantics');
      await browser.evaluate(`document.querySelector('.manual-confirm button').focus()`);await browser.enter();
      browser.check(await browser.evaluate('manualRequests.length===0'),'Review submitted without explicit confirmation');
      await browser.evaluate(`document.querySelector('#manual-confirm').checked=true;document.querySelector('.manual-confirm button').focus()`);await browser.enter();
      const request=await browser.evaluate('manualRequests.at(-1)');
      browser.check(request.method==='post'&&request.path===base&&request.fields.length===6&&request.fields.some(([k,v])=>k==='confirmed'&&v==='yes')&&request.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&request.fields.some(([k,v])=>k==='csrf'&&v==='owned-manual-csrf'),'Confirmation lost its source, revision, identity or CSRF binding');
      browser.check(await browser.evaluate(`document.querySelector('.manual-actions a').getAttribute('href').includes('q=Owned+%25_')`),'Back navigation discarded the source search');
    } else {
      browser.check(text.includes('It does not confirm execution or success')&&!text.includes('executed successfully'),'Receipt claimed successful execution from acceptance');
      browser.check(!await browser.evaluate(`!!document.querySelector('form[method="post"]')`),'Receipt contains an automatic repeat action');
      if(kind==='unconfirmed')browser.check(text.includes('may have received the command')&&text.includes('no automatic retry'),'Unconfirmed delivery hid possible execution');
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Manual execution overflows the viewport');
    if(width===390&&['choices-long','review-profile','unconfirmed'].includes(kind))await browser.capture('manual-execution-'+kind+'-390');
    record({name:'Manual execution '+kind,width,passed:true});
  }
  for(const width of [390,768,1440]) {
    await browser.visit('manual-execution-review-task',width);
    await browser.evaluate(`window.manualXHR=null;window.manualSends=0;window.manualOriginal=document.querySelector('#main').outerHTML;XMLHttpRequest.prototype.send=function(){manualXHR=this;manualSends++};document.querySelector('#manual-confirm').checked=true;document.querySelector('.manual-confirm button').focus()`);
    await browser.enter();
    browser.check(await browser.evaluate(`manualSends===1&&document.querySelector('.manual-confirm button').disabled&&document.querySelector('#manual-confirm').disabled&&document.querySelector('#manual-pending').getBoundingClientRect().height>0`),'Pending confirmation lacks a visible state or permits duplicate input');
    await browser.evaluate(`document.querySelector('.manual-confirm').requestSubmit()`);
    browser.check(await browser.evaluate('manualSends===1'),'Pending confirmation started another request');
    await browser.evaluate(`(()=>{const xhr=manualXHR;Object.defineProperties(xhr,{status:{value:200},response:{value:manualOriginal},responseText:{value:manualOriginal},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    await browser.evaluate('new Promise(resolve=>setTimeout(resolve,50))');
    browser.check(await browser.evaluate(`document.querySelectorAll('#main').length===1&&document.activeElement.id==='manual-execution-heading'`),'Confirmation response lost page focus or duplicated the main region');
    record({name:'Manual execution pending and focus',width,passed:true});
  }
}
