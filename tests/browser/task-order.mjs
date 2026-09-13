export default async function run(browser,record) {
  const setup=async(scope,width)=>{
    await browser.visit('task-order-'+scope,width);
    browser.check(await browser.evaluate(`window.openUEMProfileTasksInitialized===true && !document.body.innerText.includes('!(MISSING:')`),'Task list script or English copy is missing');
    await browser.evaluate(`window.taskOrderRequests=[];document.getElementById('owned-unsaved').value='Unsaved local profile name';document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;taskOrderRequests.push({method:d.verb,path:d.path,query:d.useUrlParams,headers:d.headers,fields:Object.fromEntries(d.formData),entries:[...d.formData.entries()]});e.preventDefault();})`);
  };
  const openAndEnter=async(index,path)=>{
    await browser.evaluate(`document.getElementById('moreButton${index}').click()`);
    await browser.evaluate(`new Promise(resolve=>setTimeout(resolve,80))`);
    await browser.evaluate(`document.querySelector('button[hx-post$=${JSON.stringify(path)}]').focus()`);
    await browser.enter();
  };
  const last=()=>browser.evaluate('taskOrderRequests.at(-1)');
  const checkRequest=async(method,path,page)=>{
    const q=await last();
    browser.check(q&&q.method===method&&q.path===path&&q.query===(method==='get'),'Task order lost its scoped method or destination');
    browser.check(q.headers['X-CSRF-Token']==='owned-csrf'&&q.entries.length===4&&q.fields.page===page&&q.fields.pageSize==='2','Task request lost context/CSRF or inherited duplicate form fields');
  };
  const saved=async(prefix,task,page,response)=>{
    await browser.evaluate(`htmx.trigger(document.body,'profileTaskOrderSaved',{profileId:'17',taskId:${JSON.stringify(task)},page:${page}})`);
    await checkRequest('get',prefix+'/profiles/17/tasks',String(page));
    await browser.evaluate(`htmx.swap('#profile-task-list',document.getElementById(${JSON.stringify(response)}).innerHTML,{swapStyle:'outerHTML'})`);
    browser.check(await browser.evaluate(`document.getElementById('owned-unsaved').value==='Unsaved local profile name'&&document.activeElement.id===${JSON.stringify('task-name-'+task)}`),'Task refresh lost unsaved metadata or focus on the moved task');
  };
  for(const width of [390,768,1440]) {
    for(const [scope,prefix] of Object.entries({global:'',organization:'/tenant/1',site:'/tenant/1/site/2'})) {
      await setup(scope,width);
      await openAndEnter(1,'/tasks/102/moveup/2');
      await checkRequest('post',prefix+'/tasks/102/moveup/2','1');
      // Status forms share this region but must not inherit its GET context twice.
      await browser.evaluate(`document.querySelector('button[hx-post$="/tasks/102/disable"]').focus()`);
      await browser.enter();
      await checkRequest('post',prefix+'/tasks/102/disable','1');
      await saved(prefix,'102',1,'owned-order-response');
      browser.check(await browser.evaluate(`[...document.querySelectorAll('#profile-task-list tbody tr')].map(row=>row.dataset.taskId).join(',')==='102,101'`),'Task page did not apply the authoritative order');
      record({name:'Task order '+scope+'/up',width,passed:true});
      await openAndEnter(1,'/tasks/101/movedown/2');
      await checkRequest('post',prefix+'/tasks/101/movedown/2','1');
      await saved(prefix,'101',2,'owned-follow-response');
      browser.check(await browser.evaluate(`document.querySelectorAll('#profile-task-list tbody tr').length===1&&document.querySelector('#profile-task-list tbody tr').dataset.order==='3'`),'Cross-page move did not follow the moved task');
      record({name:'Task order '+scope+'/follow-page',width,passed:true});
      await setup(scope,width);
      await browser.evaluate(`document.getElementById('tasks-sortable').dispatchEvent(new CustomEvent('start',{bubbles:true}))`);
      await browser.evaluate(`{const list=document.getElementById('tasks-sortable'),row=list.querySelector('[data-task-id="102"]');list.insertBefore(row,list.firstElementChild);list.dispatchEvent(new CustomEvent('moved',{bubbles:true,detail:[{},row]}));}`);
      await checkRequest('post',prefix+'/tasks/102/movefrom/2/to/1','1');
      await browser.evaluate(`document.getElementById('tasks-sortable').dispatchEvent(new CustomEvent('stop',{bubbles:true}))`);
      await saved(prefix,'102',1,'owned-order-response');
      record({name:'Task order '+scope+'/drag',width,passed:true});
      await browser.evaluate(`htmx.trigger(document.body,'htmx:responseError',{elt:document.getElementById('tasks-sortable')})`);
      await checkRequest('get',prefix+'/profiles/17/tasks','1');
      const count=await browser.evaluate('taskOrderRequests.length');
      await browser.evaluate(`htmx.trigger(document.body,'htmx:responseError',{elt:document.getElementById('profile-task-list')});htmx.trigger(document.body,'profileTaskOrderSaved',{profileId:'99',taskId:'102',page:1})`);
      browser.check(await browser.evaluate('taskOrderRequests.length')===count,'Task refresh errors looped or an unrelated profile refreshed this list');
      browser.check(await browser.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),'Task table overflows the page');
      browser.check(await browser.evaluate(`(()=>{const select=document.querySelector('#profile-task-list select'),style=getComputedStyle(select),context=document.createElement('canvas').getContext('2d');context.font=style.font;return select.value==='2'&&select.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight)>=context.measureText(select.selectedOptions[0].textContent).width})()`),'Task page-size selection is clipped or changed');
      if(width===390&&scope==='site')await browser.capture('task-order-390');
      record({name:'Task order '+scope+'/failed-drag-refresh',width,passed:true});
    }
  }
}
