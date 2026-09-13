export default async function run(browser,record) {
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      await browser.visit('task-creation-'+scope,width);
      browser.check(await browser.evaluate(`document.body.textContent.includes('Destination profile ID: 17') && document.body.textContent.includes('assigned profile')`),'Task creation omitted the destination or assignment effects');
      await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.taskCreationRequest={method:d.verb,path:d.path,headers:d.headers,fields:Array.from(d.formData.entries())};e.preventDefault();});window.taskCreationRequest=null;document.querySelector('#task-create-submit').focus()`);await browser.enter();
      browser.check(await browser.evaluate(`taskCreationRequest===null && !document.querySelector('#task-create-form').checkValidity()`),'Task creation allowed missing required fields');
      record({name:'Task creation '+scope+'/required fields',width,passed:true});
      const name='Owned <new> task\n第二行',script="Write-Output 'owned'";
      await browser.evaluate(`document.querySelector('#task-description').value=${JSON.stringify(name)};document.querySelector('#task-agent-type').value='windows';document.querySelector('#task-agent-type').dispatchEvent(new Event('change',{bubbles:true}));`);
      let q=await browser.evaluate('taskCreationRequest');browser.check(q&&q.method==='get'&&q.path==='/profiles/task-types'&&q.fields.length===1&&Object.fromEntries(q.fields)['task-agent-type']==='windows','Task type lookup included unrelated form values');
      await browser.evaluate(`htmx.swap('#select-task-type',document.querySelector('#owned-windows-types').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#task-type').value='powershell_type';document.querySelector('#task-type').dispatchEvent(new Event('change',{bubbles:true}));`);
      q=await browser.evaluate('taskCreationRequest');browser.check(q&&q.method==='get'&&q.path==='/profiles/task-subtypes'&&q.fields.length===1&&Object.fromEntries(q.fields)['task-type']==='powershell_type','Task subtype lookup included unrelated form values');
      await browser.evaluate(`htmx.swap('#task-definition',document.querySelector('#owned-powershell-definition').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#powershell-script').value=${JSON.stringify(script)};document.querySelector('#powershell-run').value='always';taskCreationRequest=null;document.querySelector('#task-create-submit').focus()`);await browser.enter();
      q=await browser.evaluate('taskCreationRequest');let fields=q&&Object.fromEntries(q.fields);
      browser.check(q&&q.method==='post'&&q.path===prefix+'/tasks/17/new'&&q.fields.length===5&&fields['task-description']===name&&fields['powershell-script']===script&&fields['task-agent-type']==='windows'&&fields['powershell-run']==='always'&&q.headers['X-CSRF-Token']==='owned-csrf','Task creation lost its source, definition, parameters or CSRF');
      record({name:'Task creation '+scope+'/native script submission',width,passed:true});
      if(width===390&&scope==='site')await browser.capture('task-creation-site-390');
      await browser.evaluate(`document.querySelector('#task-type').value='registry_type';document.querySelector('#task-type').dispatchEvent(new Event('change',{bubbles:true}));`);
      browser.check(await browser.evaluate(`document.querySelector('#powershell-script')===null`),'Changing task type retained its previous script');
      await browser.evaluate(`htmx.swap('#select-task-subtype',document.querySelector('#owned-registry-subtypes').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#task-type').value='powershell_type';document.querySelector('#task-type').dispatchEvent(new Event('change',{bubbles:true}));`);
      browser.check(await browser.evaluate(`document.querySelector('#task-subtype')===null`),'Script task kept a hidden required subtype selector');
      await browser.evaluate(`htmx.swap('#task-definition',document.querySelector('#owned-powershell-definition').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#powershell-script').value=${JSON.stringify(script)};document.querySelector('#task-agent-type').value='linux';document.querySelector('#task-agent-type').dispatchEvent(new Event('change',{bubbles:true}));`);
      browser.check(await browser.evaluate(`document.querySelector('#task-type')===null && document.querySelector('#powershell-script')===null && document.querySelector('#task-description').value===${JSON.stringify(name)}`),'Changing platform kept an incompatible definition or lost the edited name');
      record({name:'Task creation '+scope+'/clear dependent fields',width,passed:true});
      if(scope!=='global') {
        await browser.evaluate(`document.querySelector('#task-agent-type').value='any';document.querySelector('#task-agent-type').dispatchEvent(new Event('change',{bubbles:true}));htmx.swap('#select-task-type',document.querySelector('#owned-any-types').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#task-type').value='netbird_type';document.querySelector('#task-type').dispatchEvent(new Event('change',{bubbles:true}));htmx.swap('#select-task-subtype',document.querySelector('#owned-netbird-subtypes').innerHTML,{swapStyle:'innerHTML'});document.querySelector('#task-subtype').value='netbird_register';document.querySelector('#task-subtype').dispatchEvent(new Event('change',{bubbles:true}));htmx.swap('#task-definition',document.querySelector('#owned-netbird-definition').innerHTML,{swapStyle:'innerHTML'});`);
        browser.check(await browser.evaluate(`document.querySelector('#netbird-groups option[value="opaque-ID-1"]').selected && document.querySelector('#netbird-groups').textContent.includes('group-with-hyphens')`),'NetBird groups lost their labels or existing selection');
        await browser.evaluate(`for(const option of document.querySelector('#netbird-groups').options) option.selected=true;taskCreationRequest=null;document.querySelector('#task-create-submit').focus()`);await browser.enter();q=await browser.evaluate('taskCreationRequest');
        browser.check(q&&q.method==='post'&&q.path===prefix+'/tasks/17/new'&&q.fields.length===6&&JSON.stringify(q.fields.filter(([key])=>key==='netbird-group-id').map(([,value])=>value))===JSON.stringify(['opaque-ID-1','opaque-ID-2']),'NetBird group submission split IDs, included labels or lost multiple values');
        record({name:'Task creation '+scope+'/native NetBird groups',width,passed:true});
      }
      await browser.evaluate(`taskCreationRequest=null;document.querySelector('#task-create-form a').focus()`);await browser.enter();q=await browser.evaluate('taskCreationRequest');
      browser.check(q&&q.method==='get'&&q.path===prefix+'/profiles/17'&&q.fields.length===0,'Task creation cancellation included definition data or lost the destination profile');
      record({name:'Task creation '+scope+'/cancel',width,passed:true});
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task creation form overflows');
    }
    await browser.visit('task-creation-long',width);
    browser.check(await browser.evaluate(`document.body.textContent.includes('name is shortened') && document.documentElement.scrollWidth<=innerWidth+1`),'Long task destination was silently shortened or overflows');
    if(width===390)await browser.capture('task-creation-long-390');
    record({name:'Task creation long destination',width,passed:true});
  }
}
