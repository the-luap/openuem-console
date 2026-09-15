export default async function run(browser, record) {
  for (const width of [390, 768, 1440]) {
    for (const kind of ['new', 'configured', 'empty', 'shared', 'saved', 'long']) {
      await browser.visit('netbird-settings-' + kind, width);
      browser.check(await browser.evaluate(`document.documentElement.scrollWidth <= innerWidth+1 && document.querySelector('#netbird-token').value==='' && !document.querySelector('#netbird-token').hasAttribute('value') && document.querySelector('#netbird-token').autocomplete==='new-password' && document.querySelector('#netbird-token-action').value==='keep' && document.querySelector('#netbird-settings').getAttribute('hx-history')==='false'`), 'NetBird page overflows, exposes a token or retains sensitive history');
      browser.check(await browser.evaluate(`document.querySelector('#netbird-save-form').method==='post' && document.querySelector('#netbird-url').required`), 'NetBird settings lack native form submission or required URL');
      await browser.evaluate(`window.netbirdRequest=null;document.addEventListener('submit',event=>{event.preventDefault();event.stopImmediatePropagation();netbirdRequest={path:new URL(event.target.action).pathname,fields:[...new FormData(event.target)]}},true);document.querySelector('#netbird-save').focus()`);
      await browser.enter();
      let request=await browser.evaluate('netbirdRequest'); let fields=request && Object.fromEntries(request.fields);
      browser.check(request && request.path==='/tenant/1/admin/netbird' && request.fields.length===6 && fields.csrf==='owned-netbird-csrf' && fields.revision==='a'.repeat(64) && fields['token-action']==='keep' && fields.token==='' && fields.settingsId===(kind==='new'?'0':'17'), 'NetBird save lost its exact scope, revision or explicit keep action');
      if(kind==='configured') {
        await browser.evaluate(`netbirdRequest=null;document.querySelector('#netbird-token-action').value='replace';document.querySelector('#netbird-token').value='owned-new-token';document.querySelector('#netbird-save').focus()`);await browser.enter();
        fields=Object.fromEntries((await browser.evaluate('netbirdRequest')).fields);
        browser.check(fields['token-action']==='replace' && fields.token==='owned-new-token','NetBird replacement lost the new literal token');
        await browser.evaluate(`netbirdRequest=null;document.querySelector('#netbird-token-action').value='clear';document.querySelector('#netbird-token').value='';document.querySelector('#netbird-save').focus()`);await browser.enter();
        fields=Object.fromEntries((await browser.evaluate('netbirdRequest')).fields);
        browser.check(fields['token-action']==='clear' && fields.token==='','NetBird clear lost its explicit action');
      }
      if(kind==='shared') browser.check(await browser.evaluate(`document.querySelector('#netbird-shared').textContent.includes('separate copy for this organization')`),'Shared NetBird settings hide the effect of saving');
      if(kind==='new') browser.check(await browser.evaluate(`document.querySelector('#netbird-new').textContent.includes('Saving creates it')`),'Missing NetBird configuration appears persisted already');
      record({name:'NetBird settings '+kind,width,passed:true});
      if(width===390 && ['new','shared','long'].includes(kind)) await browser.capture('netbird-settings-'+kind+'-390');
    }
    await browser.visit('netbird-settings-configured',width);
    await browser.evaluate(`window.netbirdPending=null;window.netbirdPendingCalls=0;XMLHttpRequest.prototype.send=function(){netbirdPending=this;netbirdPendingCalls++};document.querySelector('#netbird-save').focus()`);await browser.enter();
    browser.check(await browser.evaluate(`!!netbirdPending && document.querySelector('#netbird-save').disabled`),'NetBird save stays active while pending');
    await browser.evaluate(`document.querySelector('#netbird-save').click()`);
    browser.check(await browser.evaluate('netbirdPendingCalls===1'),'NetBird pending submission was duplicated');
    await browser.evaluate(`(()=>{const xhr=netbirdPending;Object.defineProperties(xhr,{status:{value:204},response:{value:''},responseText:{value:''},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    browser.check(await browser.evaluate(`!document.querySelector('#netbird-save').disabled`),'NetBird save did not recover after completion');
    record({name:'NetBird settings pending controls',width,passed:true});
  }
}
