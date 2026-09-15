export default async function run(browser, record) {
  for (const width of [390,768,1440]) {
    await browser.visit('profile-audience-actions',width);
    await browser.evaluate(`window.confirm=message=>{window.profileAudienceQuestion=message;return window.profileAudienceApproved;};document.body.addEventListener('htmx:configRequest',e=>{
      const d=e.detail; window.profileAudienceRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();
    })`);
    for (const [i,path] of ['/tenant/1/profiles/17/setglobal','/tenant/1/site/2/profiles/17/setglobal','/tenant/1/site/2/profiles/17/settenant'].entries()) {
      for (const approved of [false,true]) {
        await browser.evaluate(`window.profileAudienceRequest=null;window.profileAudienceQuestion=null;window.profileAudienceApproved=${approved};document.querySelector('#profile-audience-${i} button').focus()`);
        await browser.enter();
        const r=await browser.evaluate('({request:profileAudienceRequest,question:profileAudienceQuestion})');
        browser.check(r.question && r.question.includes(i===2?'every site in this organization':'all organizations') && r.question.includes('when enabled'),'Profile audience confirmation must explain the expanded scope and preserve enabled behavior');
        if (!approved) browser.check(r.request===null,'Canceling an audience move still sent a request');
        else {
          const q=r.request;
          browser.check(q && q.method==='post' && q.path===path && !q.query,'Profile audience move lost its source scope or destination action');
          browser.check(q.headers['X-CSRF-Token']==='owned-csrf','Profile audience move lost its CSRF header');
          browser.check(Object.keys(q.fields).length===4 && q.fields.page==='2' && q.fields.pageSize==='25' && q.fields.sortBy==='name' && q.fields.sortOrder==='asc','Profile audience move lost list context or added a destination override');
        }
        record({name:'Profile audience '+path+(approved?' confirm':' cancel'),width,passed:true});
      }
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile audience buttons overflow');
    if(width===390)await browser.capture('profile-audience-actions-390');
  }
}
