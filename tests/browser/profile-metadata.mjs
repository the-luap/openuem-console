export default async function run(browser, record) {
  const editedName = "Edited <metadata>\n第二行";
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      for(const state of ['none','all','tags','all-with-tags']) {
        const fixture='profile-metadata-'+scope+'-'+state;
        await browser.visit(fixture,width);
        const initial=await browser.evaluate(`({name:document.querySelector('#profile-description').value,mode:document.querySelector('#profile-assignment').value,selected:document.querySelectorAll('#profile-assignment option[selected]').length})`);
        const expected=state==='tags'?'useTags':state==='none'?'dontApplyToAll':'applyToAll';
        browser.check(initial.name==='Owned <metadata>\n第二行' && initial.mode===expected && initial.selected===1,'Profile editor changed stored content or selected multiple assignment modes');
        await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.profileMetadataRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();})`);
        for(const mode of ['useTags','applyToAll','dontApplyToAll']) {
          await browser.evaluate(`{window.profileMetadataRequest=null;document.querySelector('#profile-description').value=${JSON.stringify(editedName)};const select=document.querySelector('#profile-assignment');select.value=${JSON.stringify(mode)};select.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('button').focus()}`);
          await browser.enter();
          const r=await browser.evaluate(`({request:profileMetadataRequest,visibility:getComputedStyle(document.querySelector('#profile-tags')).visibility,focused:document.activeElement===document.querySelector('button'),ring:getComputedStyle(document.querySelector('button')).boxShadow})`);
          browser.check(r.visibility===(mode==='useTags'?'visible':'hidden'),'Profile assignment mode did not update tag visibility');
          browser.check(r.focused && r.ring!=='none','Profile save has no visible keyboard focus in the default theme');
          const q=r.request;
          browser.check(q && q.method==='post' && q.path===prefix+'/profiles/17' && !q.query && q.headers['X-CSRF-Token']==='owned-csrf','Profile save lost its scope, method or CSRF header');
          browser.check(Object.keys(q.fields).length===2 && q.fields['profile-description']==='Edited <metadata>\n第二行' && q.fields['profile-assignment']===mode,'Profile save omitted an edited field or added another target');
        }
        browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile editor fields overflow');
        if(width===390&&scope==='site'&&state==='all-with-tags')await browser.capture('profile-metadata-390');
        record({name:'Profile metadata '+scope+'/'+state,width,passed:true});
      }
    }
  }
}
