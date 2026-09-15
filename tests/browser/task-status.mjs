export default async function run(browser,record) {
  for(const width of [390,768,1440]) {
    await browser.visit('task-status-actions',width);
    await browser.evaluate(`document.getElementById('owned-unsaved').value='Unsaved local change';document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.taskStatusRequest={method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData)};e.preventDefault();})`);
    for(const [i,prefix] of ['', '/tenant/1','/tenant/1/site/2'].entries()) {
      for(const [j,disabled] of [true,false].entries()) {
        const id=17+i*2+j,action=disabled?'enable':'disable';
        await browser.evaluate(`window.taskStatusRequest=null;document.getElementById('task-status-button-${id}').focus()`);
        await browser.enter();
        const r=await browser.evaluate('taskStatusRequest');
        browser.check(r&&r.method==='post'&&r.path===prefix+'/tasks/'+id+'/'+action&&!r.query,'Task status lost its route scope or action');
        browser.check(r.headers['X-CSRF-Token']==='owned-csrf','Task status lost its CSRF header');
        browser.check(Object.keys(r.fields).length===4&&r.fields.page==='2'&&r.fields.pageSize==='50'&&r.fields.sortBy==='name'&&r.fields.sortOrder==='asc','Task status changed list context or submitted another target');
        browser.check(await browser.evaluate(`document.getElementById('task-status-button-${id}').getAttribute('hx-target')==='closest form'&&document.getElementById('task-status-button-${id}').getAttribute('hx-disabled-elt')==='this'`),'Task status lost its local target or pending button behavior');
        // Apply the real rendered response through the bundled HTMX swap API.
        // This exercises out-of-band state and focus without a writable fixture server.
        await browser.evaluate(`htmx.swap('#task-status-action-${id}',document.getElementById('task-response-${id}').innerHTML,{swapStyle:'outerHTML'})`);
        browser.check(await browser.evaluate(`document.getElementById('task-status-state-${id}').dataset.disabled===${JSON.stringify(String(!disabled))}`),'Task indicator did not update from the rendered response');
        browser.check(await browser.evaluate(`document.getElementById('task-status-state-${id}').getAttribute('role')==='img'&&document.getElementById('task-status-state-${id}').getAttribute('aria-label')===${JSON.stringify(disabled?'Task enabled.':'Task disabled.')}`),'Task indicator lost its accessible status');
        browser.check(await browser.evaluate(`document.getElementById('owned-unsaved').value==='Unsaved local change'&&document.querySelector('#task-status-action-${id} [role=status]').textContent===${JSON.stringify(disabled?'Task enabled.':'Task disabled.')}`),'Task response replaced unsaved edits or lost its accessible confirmation');
        browser.check(await browser.evaluate(`document.activeElement.id==='task-status-button-${id}'`),'Task status response lost keyboard focus');
        await browser.enter();
        const next=await browser.evaluate('taskStatusRequest');
        browser.check(next&&next.path===prefix+'/tasks/'+id+'/'+(disabled?'disable':'enable'),'Updated task button did not offer the inverse action');
        record({name:'Task status '+(prefix||'global')+'/'+action,width,passed:true});
      }
    }
    browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task status controls overflow');
    if(width===390)await browser.capture('task-status-actions-390');
  }
}
