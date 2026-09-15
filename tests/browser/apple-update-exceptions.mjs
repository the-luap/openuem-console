export default async function run(browser,record) {
  for(const state of ['new','active','expired','ended','inactive','no-notification','receipt-pause','receipt-resume','history','empty','long'])for(const width of [390,768,1440]) {
    await browser.visit('apple-update-exception-'+state,width);
    const view=await browser.evaluate(`(()=>{
      const main=document.querySelector('[data-update-exception-page]');
      return {width:document.documentElement.scrollWidth,viewport:innerWidth,page:main.dataset.updateExceptionPage,text:main.textContent,scripts:main.querySelectorAll('script').length,
        forms:[...main.querySelectorAll('form')].map(f=>({kind:f.elements.kind.value,key:f.elements.request_key.value,token:f.elements.review_token.value,csrf:f.elements.csrf.value,action:f.getAttribute('action'),confirm:f.elements.confirmed.required,expiry:!!f.elements.expires_at})),links:[...main.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))};
    })()`);
    browser.check(view.width<=view.viewport+1&&view.scripts===0,'Exception page overflows or renders executable reason markup');
    const editable=['new','active','expired','ended','no-notification','long'].includes(state);
    browser.check(view.forms.length===(editable?(['active','long'].includes(state)?2:1):0),'Exception action availability changed');
    browser.check(view.forms.every(f=>f.confirm&&f.token==='a'.repeat(64)&&f.csrf==='owned-csrf'&&f.action==='/tenant/1/site/1/ios/10000000-0000-4000-8000-000000000001/update-exceptions'&&f.expiry===(f.kind==='pause')),'Exception form lost review, scope, CSRF or confirmation');
    browser.check(new Set(view.forms.map(f=>f.key)).size===view.forms.length,'Different exception actions share one request identity');
    if(view.page==='review')browser.check(view.text.includes('does not restore a previous policy')&&view.text.includes('including if it later returns')&&view.text.includes('An update already in progress may continue'),'Exception review hides restoration, placement or installation limits');
    if(state==='active')browser.check(view.text.includes('New update policy assignments are paused')&&view.text.includes('No update policy is configured before this action'),'Active exception lost separate policy state');
    if(state==='expired')browser.check(view.text.includes('exception has expired'),'Expired exception appears active');
    if(state==='ended')browser.check(view.text.includes('exception was ended'),'Ended exception appears active');
    if(state==='inactive')browser.check(view.text.includes('No exception action is available'),'Inactive enrollment can mutate an exception');
    if(state==='no-notification')browser.check(view.text.includes('No declarative-management notification is available'),'Unsupported notification was promised');
    if(view.page==='receipt')browser.check(view.text.includes('immutable receipt records the original action')&&view.text.includes('current exception, policy and device placement may have changed'),'Original receipt claims current state');
    if(state==='receipt-resume')browser.check(view.text.includes('no device command was queued by this action')&&!view.text.includes('Requested exception expiry'),'Resume invents policy restoration or expiry');
    if(state==='history')browser.check(view.links.filter(a=>a.text==='Open original exception event').length===2&&view.links.some(a=>a.text==='Older exception events'&&a.href.endsWith('?before=60000000-0000-4000-8000-000000000001')),'History lost original events or cursor');
    if(state==='empty')browser.check(view.text.includes('No exception events are recorded on this page')&&!view.links.some(a=>a.text==='Older exception events'),'Empty history invented events');
    if(view.forms.length) {
      await browser.evaluate(`(()=>{
        window.exceptionSubmissions=[];
        for(const f of document.querySelectorAll('[data-update-exception-page] form')) {
          f.addEventListener('submit',e=>{e.preventDefault();window.exceptionSubmissions.push(Object.fromEntries(new FormData(f,e.submitter)));});
          f.elements.reason.value='Owned keyboard maintenance';
          if(f.elements.expires_at)f.elements.expires_at.value='2026-09-13T12:00';
        }
      })()`);
      for(let i=0;i<view.forms.length;i++) {
        await browser.evaluate(`document.querySelectorAll('[data-update-exception-page] form')[${i}].querySelector('button[type="submit"]').focus()`);await browser.enter();
        browser.check(await browser.evaluate('window.exceptionSubmissions.length')===i,'Unconfirmed keyboard action was submitted');
        await browser.evaluate(`document.querySelectorAll('[data-update-exception-page] form')[${i}].elements.confirmed.focus()`);await browser.space();
        await browser.evaluate(`document.querySelectorAll('[data-update-exception-page] form')[${i}].querySelector('button[type="submit"]').focus()`);await browser.enter();
      }
      const submissions=await browser.evaluate('window.exceptionSubmissions');
      browser.check(submissions.length===view.forms.length&&submissions.every((f,i)=>f.confirmed==='yes'&&f.review_token===view.forms[i].token&&f.request_key===view.forms[i].key&&f.kind===view.forms[i].kind),'Confirmed keyboard action lost its original reviewed state');
    }
    if(width===390){await browser.evaluate("document.querySelector('[data-update-exception-page]').scrollIntoView({block:'start'})");await browser.capture('apple-update-exception-'+state+'-390');}
    record({name:'Apple update exception '+state,width,passed:true});
  }
}
