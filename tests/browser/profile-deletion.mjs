export default async function run(browser,record) {
  for(const width of [390,768,1440]) {
    for(const [state,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2',long:'/tenant/1/site/2'})) {
      await browser.visit('profile-deletion-'+state,width);
      browser.check(await browser.evaluate(`document.body.textContent.includes('Profile ID: 17') && document.body.textContent.includes('stored results') && document.body.textContent.includes('cancel tasks already sent')`),'Profile deletion omitted the target or deletion consequences');
      if(state==='long')browser.check(await browser.evaluate(`document.body.textContent.includes('name is shortened')`),'Long deletion target was silently truncated');
      await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.profileDeletionRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();})`);
      for(const [selector,method,path] of [['a','get',prefix+'/profiles'],['button','delete',prefix+'/profiles/17']]) {
        await browser.evaluate(`window.profileDeletionRequest=null;document.querySelector(${JSON.stringify(selector)}).focus()`);
        await browser.enter();
        const q=await browser.evaluate('profileDeletionRequest');
        browser.check(q && q.method===method && q.path===path && q.query && Object.keys(q.fields).length===0,'Profile deletion/cancellation sent the wrong action, scope or extra target data');
        browser.check(q.headers['X-CSRF-Token']==='owned-csrf','Profile deletion lost its CSRF header');
        if(method==='delete')browser.check(!q.headers['Content-Type'] || q.headers['Content-Type']==='application/x-www-form-urlencoded','Bundled DELETE changed its request encoding');
        record({name:'Profile deletion '+state+'/'+method,width,passed:true});
      }
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile deletion confirmation overflows');
      if(width===390 && (state==='site'||state==='long'))await browser.capture('profile-deletion-'+state+'-390');
    }
  }
}
