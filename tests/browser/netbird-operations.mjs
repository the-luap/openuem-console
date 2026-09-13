export default async function run(browser, record) {
  const kinds = ['overview','overview-empty','overview-long','overview-viewer','review-up','review-down','review-switch','review-long','queued','sending','completed','stopped','unconfirmed','released','history','history-empty','resolution-completed','resolution-release','resolution-pending','resolution-confirmed','resolution-waiting','resolution-missing','resolution-conflict','resolution-long'];
  const base = '/tenant/1/site/2/computers/owned-device/netbird/operations';
  for (const width of [390,768,1440]) for (const kind of kinds) {
    await browser.visit('netbird-operations-'+kind,width);
    const text = await browser.evaluate('document.body.innerText');
    browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size`),'NetBird page has duplicate IDs');
    browser.check(!text.includes('@netbird')&&!text.includes('!(MISSING:')&&!await browser.evaluate('!!document.querySelector("Berlin")'),'NetBird content became markup or was not rendered');
    if (kind.startsWith('review')) {
      browser.check(text.includes('interrupt access')&&text.includes('Delivery is attempted once'),'Review omitted connection impact or uncertainty');
      await browser.evaluate(`window.netbirdRequests=[];document.body.addEventListener('htmx:configRequest',e=>{netbirdRequests.push({method:e.detail.verb,path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-submit').focus()`);
      await browser.enter();
      browser.check(await browser.evaluate('netbirdRequests.length===0'),'NetBird submitted without confirmation');
      await browser.evaluate(`document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);
      await browser.enter();
      const request = await browser.evaluate('netbirdRequests.at(-1)');
      const operation = kind==='review-up'?'up':kind==='review-down'?'down':'switchprofile';
      browser.check(request?.method==='post'&&request.path===base&&request.fields.length===6&&request.fields.some(([k,v])=>k==='operation'&&v===operation)&&request.fields.some(([k,v])=>k==='revision'&&v==='a'.repeat(64))&&request.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'NetBird confirmation lost exact command or CSRF fields');
    } else if (kind.startsWith('overview')) {
      browser.check(text.includes('Reported device state'),'Overview presented reports as live execution evidence');
      if (kind==='overview-viewer') browser.check(!text.includes('Review connect')&&!text.includes('Review profile switch'),'Reader was offered management controls');
      else if (kind==='overview-empty') browser.check(await browser.evaluate('document.querySelector("#netbird-profile").disabled'),'Empty profile list remains selectable');
      else {
        await browser.evaluate(`window.netbirdProfile=null;document.querySelector('.netbird-profile').addEventListener('submit',e=>{e.preventDefault();netbirdProfile=[...new FormData(e.target)]});document.querySelector('#netbird-profile').selectedIndex=1;document.querySelector('.netbird-profile button').focus()`);await browser.enter();
        const fields=await browser.evaluate('netbirdProfile');
        browser.check(fields?.some(([k,v])=>k==='profile'&&v===(kind==='overview-long'?'p'.repeat(256):'owned-profile')),'Profile review used a display label instead of exact handle');
      }
    } else if (kind.startsWith('resolution-')) {
      browser.check(text.includes('The original outcome remains unconfirmed')&&text.includes('does not repeat the command'),'Resolution changed the original outcome or hid its effect');
      const enabled=['resolution-completed','resolution-release','resolution-pending','resolution-long'].includes(kind);
      browser.check(await browser.evaluate(`!!document.querySelector('.netbird-confirm')`)===enabled,'Resolution offered an ineligible action');
      if (enabled) {
        await browser.evaluate(`window.netbirdRequests=[];document.body.addEventListener('htmx:configRequest',e=>{netbirdRequests.push({path:e.detail.path,fields:[...e.detail.formData.entries()]});e.preventDefault()});document.querySelector('#netbird-submit').focus()`);await browser.enter();
        browser.check(await browser.evaluate('netbirdRequests.length===0'),'Resolution submitted without confirmation');
        await browser.evaluate(`document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
        const req=await browser.evaluate('netbirdRequests.at(-1)');
        const pending=kind==='resolution-pending';
        browser.check(req?.path===base+'/10000000-0000-4000-8000-000000000001/resolution'+(pending?'/reconcile':'')&&req.fields.length===(pending?3:4)&&req.fields.some(([k,v])=>k==='resolution_id'&&v==='10000000-0000-4000-8000-000000000004')&&req.fields.some(([k,v])=>k==='csrf'&&v==='owned-netbird-csrf'),'Resolution lost exact request, retained resolution ID or CSRF');
        if (pending) browser.check(text.includes('does not send another release')&&!req.fields.some(([k])=>k==='revision'),'Receipt check was presented as another release');
      }
      if (kind==='resolution-confirmed') browser.check(text.includes('Resolution confirmed'),'Confirmed resolution lacks its evidence state');
    } else if (kind==='unconfirmed'||kind==='released') {
      browser.check(text.includes('Execution is unconfirmed')&&!text.includes('Command execution confirmed')&&!await browser.evaluate(`!!document.querySelector('form[method="post"]')`),'Uncertainty was upgraded or offered an automatic repeat');
    } else if (kind==='queued') {
      browser.check(await browser.evaluate(`!!document.querySelector('#netbird-cancel[required]')`),'Queued cancellation omitted explicit intent');
    } else if (kind==='sending') {
      browser.check(!await browser.evaluate(`!!document.querySelector('#netbird-cancel')`),'In-flight receipt offered pre-delivery cancellation');
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'NetBird page overflows the viewport');
    if (width===390&&['overview-long','review-switch','unconfirmed','resolution-long','resolution-pending'].includes(kind)) await browser.capture('netbird-operations-'+kind+'-390');
    record({name:'NetBird operations '+kind,width,passed:true});
  }
  for (const width of [390,768,1440]) {
    await browser.visit('netbird-operations-review-up',width);
    await browser.evaluate(`window.netbirdXHR=null;window.netbirdSends=0;window.netbirdOriginal=document.querySelector('#main').outerHTML;XMLHttpRequest.prototype.send=function(){netbirdXHR=this;netbirdSends++};document.querySelector('#netbird-confirm').checked=true;document.querySelector('#netbird-submit').focus()`);await browser.enter();
    browser.check(await browser.evaluate(`netbirdSends===1&&document.querySelector('#netbird-submit').disabled&&document.querySelector('#netbird-confirm').disabled&&document.querySelector('#netbird-pending').getBoundingClientRect().height>0`),'Pending NetBird request lacks visible state or allows duplicate input');
    await browser.evaluate(`document.querySelector('.netbird-confirm').requestSubmit()`);
    browser.check(await browser.evaluate('netbirdSends===1'),'Pending NetBird form submitted twice');
    await browser.evaluate(`(()=>{const xhr=netbirdXHR;Object.defineProperties(xhr,{status:{value:200},response:{value:netbirdOriginal},responseText:{value:netbirdOriginal},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    await browser.evaluate('new Promise(resolve=>setTimeout(resolve,50))');
    browser.check(await browser.evaluate(`document.querySelectorAll('#main').length===1&&document.activeElement.id==='netbird-operation-heading'`),'NetBird response lost page focus');
    record({name:'NetBird operations pending and focus',width,passed:true});
  }
}
