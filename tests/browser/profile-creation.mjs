export default async function run(browser,record) {
  const name='Owned <new>\n第二行';
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      await browser.visit('profile-creation-'+scope,width);
      await browser.evaluate(`window.profileCreationRequest=null;document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.profileCreationRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();});document.querySelector('button').focus()`);
      await browser.enter();
      browser.check(await browser.evaluate(`profileCreationRequest===null && document.querySelector('textarea').validity.valueMissing`),'Empty profile creation bypassed required name validation');
      record({name:'Profile creation '+scope+'/empty',width,passed:true});
      await browser.evaluate(`document.querySelector('textarea').value=${JSON.stringify(name)};document.querySelector('button').focus()`);
      await browser.enter();
      const q=await browser.evaluate('profileCreationRequest');
      browser.check(q && q.method==='post' && q.path===prefix+'/profiles/new' && !q.query && q.headers['X-CSRF-Token']==='owned-csrf','Profile creation lost its scope, method or CSRF header');
      browser.check(Object.keys(q.fields).length===1 && q.fields['profile-description']===name,'Profile creation changed the name or accepted an assignment/identity field');
      browser.check(await browser.evaluate(`document.querySelector('form').getAttribute('hx-disabled-elt')==='find button'`),'Profile creation lost its pending-request button configuration');
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile creation form overflows');
      if(width===390&&scope==='site')await browser.capture('profile-creation-390');
      record({name:'Profile creation '+scope+'/valid',width,passed:true});
    }
  }
}
