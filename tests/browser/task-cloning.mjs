export default async function run(browser,record) {
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      await browser.visit('task-cloning-'+scope,width);
      browser.check(await browser.evaluate(`document.body.textContent.includes('Destination profile') && document.body.textContent.includes('Source task ID: 101') && document.body.textContent.includes('first 50')`),'Task clone omitted its source or bounded destination guidance');
      await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.taskCloneRequest={method:d.verb,path:d.path,headers:d.headers,fields:Array.from(d.formData.entries())};e.preventDefault();});window.taskCloneRequest=null;document.querySelector('#task-clone-submit').focus()`);
      await browser.enter();
      browser.check(await browser.evaluate(`taskCloneRequest===null && !document.querySelector('#task-clone-target').checkValidity()`),'Task clone allowed a missing destination');
      await browser.evaluate(`document.querySelector('#task-clone-target').value='23:1:2';document.querySelector('#task-description').value='';document.querySelector('#task-clone-submit').focus()`);await browser.enter();
      browser.check(await browser.evaluate(`taskCloneRequest===null && !document.querySelector('#task-description').checkValidity()`),'Task clone allowed an empty name');
      record({name:'Task cloning '+scope+'/required fields',width,passed:true});
      const name='Owned <new> task\n第二行';
      await browser.evaluate(`document.querySelector('#task-description').value=${JSON.stringify(name)};document.querySelector('#task-clone-submit').focus()`);await browser.enter();
      let q=await browser.evaluate('taskCloneRequest');
      browser.check(q&&q.method==='post'&&q.path===prefix+'/tasks/101/clone'&&q.fields.length===3&&Object.fromEntries(q.fields)['task-description']===name&&Object.fromEntries(q.fields).target==='23:1:2'&&Object.fromEntries(q.fields)['source-profile']==='17'&&q.headers['X-CSRF-Token']==='owned-csrf','Task clone lost its exact source, selected target, name or CSRF');
      record({name:'Task cloning '+scope+'/native copy',width,passed:true});
      await browser.evaluate(`taskCloneRequest=null;document.querySelector('#task-clone-query').value='31';document.querySelector('#task-clone-search button').focus()`);await browser.enter();
      q=await browser.evaluate('taskCloneRequest');
      browser.check(q&&q.method==='get'&&q.path===prefix+'/tasks/101/clone/targets'&&q.fields.length===2&&Object.fromEntries(q.fields).q==='31'&&Object.fromEntries(q.fields)['source-profile']==='17','Task clone search leaked copy fields or lost source binding');
      const cleared=await browser.evaluate(`htmx.trigger(document.querySelector('#task-clone-search'),'htmx:beforeRequest');new Promise(resolve=>setTimeout(()=>resolve(document.querySelector('#task-clone-target').value),0))`);
      browser.check(cleared==='','A new task destination search retained the previous selection');
      await browser.evaluate(`htmx.swap('#task-clone-targets',document.querySelector('#owned-target-response').innerHTML,{swapStyle:'outerHTML'});`);
      browser.check(await browser.evaluate(`document.querySelector('#task-clone-target option[value="31:1:2"]')!==null && document.querySelector('#task-clone-target').value==='' && document.querySelector('#task-description').value===${JSON.stringify(name)}`),'Task destination lookup lost the edited name or kept a stale selection');
      record({name:'Task cloning '+scope+'/scoped search and replacement',width,passed:true});
      await browser.evaluate(`taskCloneRequest=null;document.querySelector('#task-clone-form a').focus()`);await browser.enter();q=await browser.evaluate('taskCloneRequest');
      browser.check(q&&q.method==='get'&&q.path===prefix+'/profiles/17'&&q.fields.length===0,'Task clone cancellation lost the source profile or included mutation fields');
      record({name:'Task cloning '+scope+'/cancel',width,passed:true});
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task cloning form overflows');
      if(width===390&&scope==='site')await browser.capture('task-cloning-site-390');
    }
    for(const state of ['long','empty']) {
      await browser.visit('task-cloning-'+state,width);
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task cloning edge state overflows');
      if(state==='long')browser.check(await browser.evaluate(`document.querySelector('#task-description').value.length===2048 && document.querySelector('#task-description').getBoundingClientRect().width>innerWidth*.6`),'Long task name lost usable input space');
      else browser.check(await browser.evaluate(`document.body.textContent.includes('No matching profiles') && !document.querySelector('#task-clone-form').checkValidity()`),'Empty task target search allowed copying or omitted its explanation');
      if(width===390)await browser.capture('task-cloning-'+state+'-390');
      record({name:'Task cloning '+state,width,passed:true});
    }
  }
}
