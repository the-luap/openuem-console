export default async function run(browser,record) {
  const name='Owned <clone>\n第二行';
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      await browser.visit('profile-cloning-'+scope,width);
      browser.check(await browser.evaluate(`!document.body.innerText.includes('!(MISSING:') && document.querySelector('label[for="tenant-id"]').innerText==='Destination organization'`),'Clone has missing English labels');
      await browser.evaluate(`window.profileCloneRequests=[];document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;profileCloneRequests.push({method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)});e.preventDefault();});document.querySelector('textarea').value='';document.querySelector('button').focus()`);
      await browser.enter();
      browser.check(await browser.evaluate(`profileCloneRequests.length===0 && document.querySelector('textarea').validity.valueMissing`),'Clone accepted an empty profile name');
      record({name:'Profile cloning '+scope+'/empty',width,passed:true});
      await browser.evaluate(`document.querySelector('textarea').value=${JSON.stringify(name)};document.querySelector('button').focus()`);
      await browser.enter();
      const checkClone=async(tenant,site)=>{
        const q=await browser.evaluate('profileCloneRequests.at(-1)');
        browser.check(q && q.method==='post' && q.path===prefix+'/profiles/17/clone' && !q.query && q.headers['X-CSRF-Token']==='owned-csrf','Clone lost its source scope, POST or CSRF');
        browser.check(q.fields['profile-description']===name && q.fields['tenant-id']===tenant && (site===undefined?!('site-id' in q.fields):q.fields['site-id']===site),'Clone changed the name or destination');
        browser.check(Object.keys(q.fields).length===(site===undefined?2:3),'Clone submitted an unexpected field');
      };
      await checkClone('',undefined);
      browser.check(await browser.evaluate(`document.querySelector('a').getAttribute('href')===${JSON.stringify(prefix+'/profiles')}`),'Clone cancel lost the source list');
      record({name:'Profile cloning '+scope+'/global',width,passed:true});
      const selectOrganization=async(value,response)=>{
        await browser.evaluate(`document.getElementById('tenant-id').value=${JSON.stringify(value)};document.getElementById('tenant-id').dispatchEvent(new Event('change',{bubbles:true}))`);
        const q=await browser.evaluate('profileCloneRequests.at(-1)');
        browser.check(q && q.method==='post' && q.path==='/tenant/sites' && !q.query && q.headers['X-CSRF-Token']==='owned-csrf' && Object.keys(q.fields).length===1 && q.fields['tenant-id']===value,'Site lookup leaked clone fields or lost its organization/CSRF');
        await browser.evaluate(`document.getElementById('site-selector').outerHTML=document.getElementById(${JSON.stringify(response)}).innerHTML;htmx.process(document.getElementById('site-selector'))`);
      };
      await selectOrganization('1','owned-sites-response');
      browser.check(await browser.evaluate(`document.querySelector('label[for="site-id"]')!==null && document.getElementById('tenant-id').getAttribute('hx-sync')==='this:replace' && document.getElementById('tenant-id').getAttribute('hx-disabled-elt')==='#profile-clone-submit'`),'Site selector lost its label or pending request behavior');
      await browser.evaluate(`document.querySelector('button').focus()`);
      await browser.enter();
      await checkClone('1','');
      record({name:'Profile cloning '+scope+'/organization',width,passed:true});
      await browser.evaluate(`document.getElementById('site-id').value='2';document.querySelector('button').focus()`);
      await browser.enter();
      await checkClone('1','2');
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Clone form overflows');
      browser.check(await browser.evaluate(`document.activeElement.id==='profile-clone-submit' && getComputedStyle(document.activeElement).boxShadow!=='none'`),'Clone button lost visible keyboard focus');
      if(width===390&&scope==='site')await browser.capture('profile-cloning-390');
      await selectOrganization('','owned-empty-response');
      await browser.evaluate(`document.querySelector('button').focus()`);
      await browser.enter();
      await checkClone('',undefined);
      record({name:'Profile cloning '+scope+'/site-and-reset',width,passed:true});
    }
  }
}
