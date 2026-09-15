export default async function run(browser,record) {
  const base='/tenant/1/site/2/computers/owned-endpoint';
  for(const width of [390,768,1440])for(const kind of ['normal','empty','missing','disabled','long']) {
    await browser.visit('desktop-task-history-'+kind,width);
    const text=await browser.evaluate('document.body.innerText');
    browser.check(!text.includes('!(MISSING:')&&!text.includes('manual_execution.')&&!text.includes('@manual'),'Task history has untranslated or unrendered content');
    browser.check(await browser.evaluate(`document.querySelectorAll('[id]').length===new Set([...document.querySelectorAll('[id]')].map(e=>e.id)).size&&!document.querySelector('[uk-modal]')`),'Task history has duplicate IDs or embedded modals');
    if(kind==='empty')browser.check(text.includes('No task reports are available')&&!await browser.evaluate(`!!document.querySelector('[data-task-report]')`),'Empty report history is misleading');
    else {
      browser.check(text.includes('Failed')&&text.includes('Reported result'),'Stored task outcome was omitted');
      if(kind==='missing')browser.check(text.includes('Current task is unavailable')&&text.includes('Current profile is unavailable')&&text.includes('Owned <stdout>')&&text.includes('Owned invalid time'),'Missing definitions removed retained history');
      if(kind==='disabled')browser.check(text.includes('Task is currently disabled')&&!await browser.evaluate(`[...document.querySelectorAll('a')].some(a=>a.href.includes('/execution'))`),'Disabled computer still offers execution');
      if(kind==='long')browser.check(text.includes('4,096 characters')&&await browser.evaluate(`[...document.querySelectorAll('pre')].every(e=>e.clientHeight<=322&&getComputedStyle(e).whiteSpace==='pre-wrap'&&e.tabIndex===0)`),'Oversized report output is not bounded or keyboard scrollable');
      if(kind!=='missing')browser.check(await browser.evaluate(`[...document.querySelectorAll('a')].some(a=>a.getAttribute('href')==='/tenant/1/profiles/7/issues')`),'Profile link uses the endpoint site instead of its actual source scope');
      if(kind==='normal'||kind==='long')browser.check(await browser.evaluate(`[...document.querySelectorAll('a')].some(a=>a.getAttribute('href')==='/tenant/1/site/2/computers/owned-endpoint/execution/review?kind=task&source_id=17')`),'Task run link bypasses review or loses the target');
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task history overflows the viewport');
    if(width===390&&['missing','long'].includes(kind))await browser.capture('desktop-task-history-'+kind+'-390');
    record({name:'Desktop task history '+kind,width,passed:true});
  }
  for(const width of [390,768,1440]) {
    await browser.visit('desktop-task-history-normal',width);
    await browser.evaluate(`window.historyXHR=null;window.historyOriginal=document.querySelector('#main').outerHTML;XMLHttpRequest.prototype.send=function(){historyXHR=this};document.querySelector('nav.manual-actions a:last-child').focus()`);
    await browser.enter();
    browser.check(await browser.evaluate('!!historyXHR'),'Keyboard paging did not start a request');
    await browser.evaluate(`(()=>{const xhr=historyXHR;Object.defineProperties(xhr,{status:{value:200},response:{value:historyOriginal},responseText:{value:historyOriginal},responseURL:{value:location.origin+'/tenant/1/site/2/computers/owned-endpoint/tasks?page=3&pageSize=5'}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    await browser.evaluate('new Promise(resolve=>setTimeout(resolve,50))');
    browser.check(await browser.evaluate(`document.querySelectorAll('#main').length===1&&document.activeElement.id==='manual-execution-heading'&&location.search==='?page=3&pageSize=5'`),'Task history paging lost its page size, URL or focus');
    record({name:'Desktop task history paging and focus',width,passed:true});
  }
}
