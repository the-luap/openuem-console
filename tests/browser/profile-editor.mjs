export default async function run(browser, record) {
  const scopes={global:'',organization:'/tenant/1',site:'/tenant/1/site/2'};
  const enter=async(selector)=>{await browser.evaluate(`document.querySelector(${JSON.stringify(selector)}).focus()`);await browser.enter();};
  const last=()=>browser.evaluate('profileEditorRequests.at(-1)');
  const swap=async(id)=>browser.evaluate(`htmx.swap('#profile-tag-panel',document.getElementById(${JSON.stringify(id)}).innerHTML,{swapStyle:'outerHTML'})`);
  const preserved=async()=>browser.check(await browser.evaluate(`document.querySelector('#profile-description').value==='Unsaved <profile>\\n第二行'&&document.querySelector('#task-list-context [name="page"]').value==='2'&&document.querySelectorAll('#profile-description').length===1`),'Tag operation lost unsaved metadata or the task page');
  for(const width of [390,768,1440])for(const [scope,prefix] of Object.entries(scopes))for(const kind of ['normal','long']) {
    const recordCase=name=>record({name:'Profile editor '+scope+'/'+kind+'/'+name,width,passed:true});
    await browser.visit('profile-editor-'+scope+'-'+kind,width);
    browser.check(await browser.evaluate('window.openUEMProfileEditorInstalled===true'),'Profile editor script did not initialize');
    await browser.evaluate(`window.profileEditorRequests=[];document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;profileEditorRequests.push({method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData),entries:[...d.formData.entries()]});e.preventDefault();})`);
    const initial=await browser.evaluate(`({name:document.querySelector('#profile-description').value,mode:document.querySelector('#profile-assignment').value,forms:document.querySelectorAll('#profile-editor form form').length})`);
    browser.check(initial.forms===0&&initial.mode==='applyToAll'&&initial.name===(kind==='long'?'':'Owned <profile>\n第二行'),'Editor changed stored values or nested its forms');
    if(kind==='long') {
      await enter('#profile-metadata-form button');
      browser.check(await browser.evaluate('profileEditorRequests.length===0'),'Oversized legacy name submitted a truncated replacement');
    }
    await browser.evaluate(`document.querySelector('#profile-description').value='Unsaved <profile>\\n第二行';document.querySelector('#profile-assignment').value='dontApplyToAll'`);
    await enter('#profile-metadata-form button');
    let q=await last();
    browser.check(q&&q.method==='post'&&q.path===prefix+'/profiles/17'&&!q.query&&q.entries.length===2&&q.fields['profile-assignment']==='dontApplyToAll'&&q.fields['profile-description']==='Unsaved <profile>\n第二行'&&q.headers['X-CSRF-Token']==='owned-csrf','Metadata save inherited tag/task fields or lost its scope and CSRF header');
    browser.check(await browser.evaluate(`getComputedStyle(document.activeElement).boxShadow!=='none'`),'Metadata save has no visible keyboard focus');
    recordCase('metadata');

    await browser.evaluate(`document.querySelector('#profile-tag-choice').value='43';document.querySelector('#profile-tag-query').value='needle & <tag>'`);
    await enter('#profile-tag-search button');q=await last();
    browser.check(q&&q.method==='get'&&q.path===prefix+'/profiles/17/tags'&&q.query&&q.entries.length===2&&q.fields.q==='needle & <tag>'&&q.fields.page==='1','Tag search leaked unsaved fields or omitted its literal query');
    await browser.evaluate(`htmx.trigger(document.querySelector('#profile-tag-search'),'htmx:beforeRequest',{elt:document.querySelector('#profile-tag-search')})`);
    browser.check(await browser.evaluate(`document.querySelector('#profile-tag-choice').value===''`),'Starting a new search retained a stale tag selection');
    await swap('owned-tag-search-response');await preserved();
    browser.check(await browser.evaluate(`document.querySelector('#profile-assignment').value==='dontApplyToAll'&&document.querySelector('#profile-tag-choice').value===''`),'Read-only tag search replaced unsaved assignment or selected an arbitrary tag');
    recordCase('search');

    const count=await browser.evaluate('profileEditorRequests.length');
    await enter('#profile-tag-add button');
    browser.check(await browser.evaluate('profileEditorRequests.length')===count,'Add tag submitted without a selection');
    await browser.evaluate(`document.querySelector('#profile-tag-choice').value='44'`);
    await enter('#profile-tag-add button');q=await last();
    browser.check(q&&q.method==='post'&&q.path===prefix+'/profiles/17/tags'&&!q.query&&q.entries.length===4&&q.fields.agentId==='17'&&q.fields.tagId==='44'&&q.fields.page==='1'&&q.fields.q==='needle & <tag>'&&q.headers['X-CSRF-Token']==='owned-csrf','Add tag lost its exact selection or inherited other form fields');
    await swap('owned-tag-add-response');await preserved();
    browser.check(await browser.evaluate(`document.querySelectorAll('#profile-assignment-field').length===1&&document.querySelector('#profile-assignment').value==='useTags'&&document.querySelector('#profile-tag-choice').disabled`),'Tag mutation did not apply its assignment response or empty-result state');
    recordCase('add');

    await enter('#profile-tag-panel nav a');q=await last();
    const expected=prefix+'/profiles/17/tags?page=2&q=needle+%26+%3Ctag%3E';
    browser.check(q&&q.method==='get'&&q.path===expected&&q.entries.length===0,'Applied tag paging lost the search or inherited another form');
    await swap('owned-tag-page-response');await preserved();
    browser.check(await browser.evaluate(`document.querySelector('#profile-tag-panel nav').textContent.includes('Page 2 of 2')&&document.querySelector('#profile-assignment').value==='useTags'`),'Tag page read replaced the assignment');
    recordCase('paging');

    await enter('#profile-tag-panel form[hx-delete] button');q=await last();
    browser.check(q&&q.method==='delete'&&q.path===prefix+'/profiles/17/tags'&&q.query&&q.entries.length===4&&q.fields.agentId==='17'&&q.fields.tagId==='42'&&q.fields.page==='2'&&q.fields.q==='needle & <tag>','Remove tag lost its exact target, page or DELETE query encoding');
    await swap('owned-tag-remove-response');await preserved();
    browser.check(await browser.evaluate(`document.querySelector('#profile-assignment').value==='dontApplyToAll'&&document.querySelector('#profile-tag-panel').textContent.includes('No tags are assigned.')`),'Removing the last tag left a stale assignment');
    recordCase('remove');

    await enter('#profile-editor a[hx-get$="/tasks/17/new"]');q=await last();
    browser.check(q&&q.method==='get'&&q.path===prefix+'/tasks/17/new'&&q.entries.length===0,'Add-task navigation inherited unsaved profile or tag values');
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Profile editor overflows the viewport');
    if(width===390&&scope==='site')await browser.capture('profile-editor-'+kind+'-390');
    recordCase('navigation');
  }
  // Hold a real HTMX XMLHttpRequest at send(), then deliver the rendered response.
  // This exercises validation, serialization, disabled controls, synchronization,
  // focus restoration and cleanup without contacting any provider.
  for(const width of [390,768,1440])for(const [scope,prefix] of Object.entries(scopes)) {
    await browser.visit('profile-editor-'+scope+'-normal',width);
    await browser.evaluate(`window.profilePendingRequests=[];XMLHttpRequest.prototype.send=function(body){profilePendingRequests.push(this)};document.querySelector('#profile-description').value='Pending unsaved name';document.querySelector('#profile-tag-choice').value='43';document.querySelector('#profile-tag-query').value='needle & <tag>'`);
    await enter('#profile-tag-search button');
    browser.check(await browser.evaluate(`profilePendingRequests.length===1&&document.querySelector('#profile-tag-choice').value===''&&[...document.querySelectorAll('#profile-editor fieldset')].every(f=>f.disabled)`),'Pending search retained a stale tag choice or left mutation controls enabled');
    await browser.evaluate(`htmx.trigger(document.querySelector('#profile-tag-panel nav a'),'click')`);
    browser.check(await browser.evaluate('profilePendingRequests.length===1'),'Concurrent tag paging bypassed the profile request synchronization');
    await browser.evaluate(`(()=>{const xhr=profilePendingRequests[0],response=document.querySelector('#owned-tag-search-response').innerHTML;Object.defineProperties(xhr,{status:{value:200},response:{value:response},responseText:{value:response},responseURL:{value:location.origin+${JSON.stringify(prefix+'/profiles/17/tags')}}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload();})()`);
    browser.check(await browser.evaluate(`document.querySelector('#profile-description').value==='Pending unsaved name'&&document.activeElement.id==='profile-tag-query'&&[...document.querySelectorAll('#profile-editor fieldset')].every(f=>!f.disabled)&&document.querySelector('#profile-tag-choice option[value="44"]')!==null`),'Search response lost focus, unsaved content, or left controls disabled');
    record({name:'Profile editor '+scope+'/pending request',width,passed:true});
  }

}
