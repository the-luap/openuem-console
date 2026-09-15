export default async function run(browser, record) {
  for (const width of [390,768,1440]) {
    await browser.visit('profile-status-actions',width);
    await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{
      const d=e.detail; window.profileStatusRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();
    })`);
    for (const [i,prefix] of ['', '/tenant/1', '/tenant/1/site/2'].entries()) {
      for (const disabled of [true,false]) {
        await browser.evaluate(`window.profileStatusRequest=null;document.querySelector('#profile-status-${i}-${disabled} button').focus()`);
        await browser.enter();
        const r=await browser.evaluate('profileStatusRequest');
        const action=disabled?'enable':'disable';
        browser.check(r && r.method==='post' && r.path===prefix+'/profiles/17/'+action && !r.query,'Profile status lost its current route scope or action');
        browser.check(r.headers['X-CSRF-Token']==='owned-csrf','Profile status lost its CSRF header');
        browser.check(Object.keys(r.fields).length===4 && r.fields.page==='2' && r.fields.pageSize==='25' && r.fields.sortBy==='name' && r.fields.sortOrder==='asc','Profile status lost list context or added another target source');
        record({name:'Profile status '+(prefix||'global')+'/'+action,width,passed:true});
      }
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile status buttons overflow');
    if(width===390)await browser.capture('profile-status-actions-390');
  }
}
