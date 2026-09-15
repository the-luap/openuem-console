export default async function run(browser, record) {
  const scopes={global:'',organization:'/tenant/1',site:'/tenant/1/site/2'};
  for(const width of [390,768,1440])for(const [scope,prefix] of Object.entries(scopes))for(const kind of ['list','list-orphan','list-empty','reports','reports-orphan','reports-empty','reports-long']) {
    await browser.visit('profile-history-'+scope+'-'+kind,width);
    await browser.evaluate(`window.profileHistoryRequests=[];document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;profileHistoryRequests.push({method:d.verb,path:d.path,fields:[...d.formData.entries()]});e.preventDefault();})`);
    const content=await browser.evaluate('document.body.innerText');
    browser.check(!content.includes('!(MISSING:')&&!content.includes('@ProfileHistory'),'Profile history has unrendered template content');
    const list=kind.startsWith('list'),orphan=kind.endsWith('orphan'),empty=kind.endsWith('empty');
    browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size&&!document.querySelector('[uk-modal]')`),'History retained duplicate modal IDs');
    if(empty)browser.check(content.includes(list?'No profile reports are available.':'No task reports are available for this profile report.'),'Empty history has no explanation');
    if(orphan)browser.check(content.includes('Endpoint no longer available')&&!content.includes('Owned <endpoint>'),'Orphan history was hidden or retained an unrelated endpoint identity');
    if(list)browser.check(!content.includes('Owned <stdout>')&&!content.includes('Owned disabled task'),'History overview eagerly loaded task details');
    if(kind==='reports')browser.check(content.includes('Task is currently disabled.')&&content.includes('Result: Failed')&&content.includes('Owned <stdout> & output')&&content.includes('Owned <stderr>'),'Disabled task report, stored outcome or escaped output disappeared');
    if(kind==='reports-orphan')browser.check(content.includes('Current task is unavailable in this profile.')&&content.includes('unrecognized <time>')&&!content.includes('Owned disabled task'),'Missing task/time history was silently dropped');
    if(kind==='reports-long') {
      browser.check(content.includes('4,096 characters')&&content.includes('1,024 characters'),'Truncated outputs have no explicit notice');
      browser.check(await browser.evaluate(`[...document.querySelectorAll('pre')].every(el=>getComputedStyle(el).whiteSpace==='pre-wrap'&&el.clientHeight<=322&&el.tabIndex===0)`),'Long outputs cannot be read in a bounded keyboard-scrollable area');
    }
    if(!orphan) {
      const dates=await browser.evaluate(`[...document.querySelectorAll('time')].map(el=>({iso:el.dateTime,title:el.title,text:el.textContent}))`);
      browser.check(dates.every(d=>d.iso==='2026-03-29T01:30:45.123456789Z'&&d.title.includes('2026-03-29')&&d.text&&!d.text.includes('Invalid')),'History timestamps lost their stored instant or valid fallback');
    }
    const paths=await browser.evaluate(`[...document.querySelectorAll('a[hx-get]')].map(el=>el.getAttribute('hx-get'))`);
    if(list&&!empty) {
      browser.check(paths.includes(prefix+'/profiles/17/issues/27?issuePage=2&issuePageSize=5&page=1'),'Task report navigation omitted its parent or list page');
      browser.check(paths.includes(prefix+'/profiles/17/issues?page=1&pageSize=5')&&paths.includes(prefix+'/profiles/17/issues?page=3&pageSize=5'),'Profile report paging changed the selected size');
    }
    if(!list) {
      browser.check(paths.includes(prefix+'/profiles/17/issues?page=2&pageSize=5'),'Back navigation lost the originating history page');
      if(!empty)browser.check(paths.includes(prefix+'/profiles/17/issues/27?issuePage=2&issuePageSize=5&page=2'),'Task report paging lost its issue/parent context');
      if(!orphan&&!empty)browser.check(paths.includes(prefix+'/tasks/37'),'Current task navigation lost the selected profile scope');
    }
    if(!orphan&&!empty)browser.check(paths.includes('/tenant/1/site/2/computers/owned-endpoint'),'Endpoint navigation incorrectly used the profile scope instead of its current site');
    for(let i=0;i<paths.length;i++) {
      await browser.evaluate(`document.querySelectorAll('a[hx-get]')[${i}].focus()`);await browser.enter();
      const q=await browser.evaluate('profileHistoryRequests.at(-1)');
      browser.check(q&&q.method==='get'&&q.path===paths[i]&&q.fields.length===0,'History keyboard navigation inherited unrelated fields or changed the reviewed destination');
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile history overflows the viewport');
    if(width===390&&scope==='site'&&['list-orphan','reports','reports-long'].includes(kind))await browser.capture('profile-history-'+kind+'-390');
    record({name:'Profile history '+scope+'/'+kind,width,passed:true});
  }
  for(const width of [390,768,1440])for(const [scope,prefix] of Object.entries(scopes)) {
    await browser.visit('profile-history-'+scope+'-list',width);
    await browser.evaluate(`window.pendingHistoryXHR=null;XMLHttpRequest.prototype.send=function(){pendingHistoryXHR=this};document.body.addEventListener('htmx:configRequest',e=>{window.nativeHistoryRequest={path:e.detail.path,fields:[...e.detail.formData.entries()]}});document.querySelector('nav a:last-of-type').focus()`);await browser.enter();
    const expected=prefix+'/profiles/17/issues?page=3&pageSize=5';
    browser.check(await browser.evaluate(`pendingHistoryXHR!==null&&nativeHistoryRequest.path===${JSON.stringify(expected)}&&nativeHistoryRequest.fields.length===0`),'Native history page request lost its destination or inherited context');
    await browser.evaluate(`(()=>{const xhr=pendingHistoryXHR,response=document.querySelector('#owned-history-next-response').innerHTML;Object.defineProperties(xhr,{status:{value:200},response:{value:response},responseText:{value:response},responseURL:{value:location.origin+${JSON.stringify(expected)}}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    await browser.evaluate(`new Promise(resolve=>setTimeout(resolve,50))`);
    browser.check(await browser.evaluate(`document.activeElement.id==='profile-history-heading'&&document.querySelector('#profile-issues-page nav').textContent.includes('Page 3 of 3')&&document.querySelectorAll('#main').length===1&&location.pathname+location.search===${JSON.stringify(expected)}`),'History page swap lost focus, URL or its authoritative page');
    record({name:'Profile history '+scope+'/page focus',width,passed:true});
  }

}
