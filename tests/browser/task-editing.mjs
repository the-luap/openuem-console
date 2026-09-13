export default async function run(browser,record) {
  for(const width of [390,768,1440])for(const scope of ['global','organization','site']) {
    const prefix=scope==='global'?'':scope==='organization'?'/tenant/1':'/tenant/1/site/2';
    await browser.visit('task-order-'+scope,width);
    await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.taskEditNavigation={path:d.path,fields:Array.from(d.formData.entries())};e.preventDefault();});window.taskEditNavigation=null;document.querySelector('a[id^="task-name-"]').focus()`);await browser.enter();
    const navigation=await browser.evaluate('taskEditNavigation');
    browser.check(navigation&&navigation.path.startsWith(prefix+'/tasks/')&&navigation.fields.length===0,'Opening a task editor inherited the task list paging or unsaved profile fields');
    record({name:'Task editing '+scope+'/isolated navigation',width,passed:true});
    for(const kind of ['script','user','unix-user','netbird','long']) {
      await browser.visit('task-editing-'+scope+'-'+kind,width);
      browser.check(await browser.evaluate(`document.querySelector('#task-edit-form') && document.documentElement.scrollWidth<=innerWidth+1`),'Task edit form is missing or overflows');
      await browser.evaluate(`document.body.addEventListener('htmx:configRequest',e=>{const d=e.detail;window.taskEditRequest={method:d.verb,path:d.path,headers:d.headers,fields:Array.from(d.formData.entries())};e.preventDefault();});window.taskEditRequest=null;`);
      if(kind==='script') {
        await browser.evaluate(`document.querySelector('#task-description').value='';document.querySelector('#task-edit-submit').focus()`);await browser.enter();
        browser.check(await browser.evaluate(`taskEditRequest===null && !document.querySelector('#task-edit-form').checkValidity()`),'Task edit accepted a missing required name');
        await browser.evaluate(`document.querySelector('#task-description').value='Owned edited <name>';document.querySelector('#powershell-script').value="Write-Output 'changed'"`);
      }
      if(kind==='user'||kind==='unix-user') {
        browser.check(await browser.evaluate(`document.querySelector('[name="local-user-password"]').value==='' && document.querySelector('#task-password-action').value==='keep'`),'Task edit displayed a password or did not default to preserving it');
        if(kind==='unix-user')browser.check(await browser.evaluate(`document.querySelector('input[name="local-user-ssh-key-passphrase"]').value==='' && document.querySelector('#task-passphrase-action').value==='keep'`),'Task edit displayed an SSH passphrase or did not default to preserving it');
      }
      if(kind==='unix-user') {
        await browser.evaluate(`document.querySelector('#local-user-advanced-toggle').checked=true;document.querySelector('#local-user-advanced-toggle').dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('#task-passphrase-action').value='replace';document.querySelector('input[name="local-user-ssh-key-passphrase"]').value='new-owned-passphrase';`);
      }
      if(kind==='netbird') {
        browser.check(await browser.evaluate(`document.querySelector('option[value="saved-ID"]').selected && document.querySelector('#netbird-allow-extra-dns-labels').checked`),'Task edit lost its stored NetBird groups or DNS choice');
        await browser.evaluate(`for(const option of document.querySelector('#netbird-groups').options)option.selected=true`);
      }
      await browser.evaluate(`document.querySelector('#task-edit-submit').focus()`);await browser.enter();
      let q=await browser.evaluate('taskEditRequest'),fields=q&&Object.fromEntries(q.fields);
      browser.check(q&&q.method==='post'&&q.path===prefix+'/tasks/27'&&fields.profile==='17'&&fields['task-version']==='7'&&fields['selected-task-type']&&fields['task-agent-type']&&q.headers['X-CSRF-Token']==='owned-csrf','Task edit lost its reviewed parent, version, immutable type/platform or CSRF');
      if(kind==='script')browser.check(q.fields.length===7&&fields['powershell-script']==="Write-Output 'changed'",'Task edit script submission included duplicated targeting or lost edited content');
      if(kind==='user'||kind==='unix-user')browser.check(fields['task-password-action']==='keep'&&fields['local-user-password']==='','Default save did not preserve the hidden password');
      if(kind==='unix-user')browser.check(fields['task-passphrase-action']==='replace'&&fields['local-user-ssh-key-passphrase']==='new-owned-passphrase'&& !('local-user-advanced-toggle' in fields),'Advanced SSH editing lost its explicit value or submitted a display-only toggle');
      if(kind==='netbird')browser.check(JSON.stringify(q.fields.filter(([key])=>key==='netbird-group-id').map(([,value])=>value))===JSON.stringify(['saved-ID','new-ID']),'Task edit dropped a saved NetBird group or the new selection');
      record({name:'Task editing '+scope+'/'+kind+'/native save',width,passed:true});
      if(width===390&&scope==='site')await browser.capture('task-editing-'+kind+'-390');
      if(kind==='user') {
        await browser.evaluate(`document.querySelector('#task-password-action').value='replace';document.querySelector('[name="local-user-password"]').value='new-owned-password';taskEditRequest=null;document.querySelector('#task-edit-submit').focus()`);await browser.enter();q=await browser.evaluate('taskEditRequest');fields=q&&Object.fromEntries(q.fields);
        browser.check(fields&&fields['task-password-action']==='replace'&&fields['local-user-password']==='new-owned-password','Explicit replacement lost its password or action');
        await browser.evaluate(`document.querySelector('#task-password-action').value='clear';document.querySelector('[name="local-user-password"]').value='';taskEditRequest=null;document.querySelector('#task-edit-submit').focus()`);await browser.enter();q=await browser.evaluate('taskEditRequest');fields=q&&Object.fromEntries(q.fields);
        browser.check(fields&&fields['task-password-action']==='clear'&&fields['local-user-password']==='','Explicit password clearing lost its action');
        record({name:'Task editing '+scope+'/explicit password changes',width,passed:true});
      }
      await browser.evaluate(`taskEditRequest=null;document.querySelector('#task-edit-form a').focus()`);await browser.enter();q=await browser.evaluate('taskEditRequest');
      browser.check(q&&q.method==='get'&&q.path===prefix+'/profiles/17'&&q.fields.length===0,'Task edit cancellation leaked configuration or lost the reviewed parent');
      record({name:'Task editing '+scope+'/'+kind+'/cancel',width,passed:true});
    }
  }
}
