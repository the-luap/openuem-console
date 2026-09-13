export default async function run(browser, record) {
  for (const width of [390, 768, 1440]) for (const scope of ['global', 'organization']) {
    const base = scope === 'global' ? '/admin/smtp' : '/tenant/1/admin/smtp';
    for (const kind of ['normal', 'empty', 'saved', 'sent', 'unconfirmed', 'changed', 'long']) {
      await browser.visit('smtp-settings-' + scope + '-' + kind, width);
      browser.check(await browser.evaluate(`document.documentElement.scrollWidth<=innerWidth+1 && document.querySelector('#smtp-password').value==='' && !document.querySelector('#smtp-password').hasAttribute('value') && document.querySelector('#smtp-password-action').value==='keep' && !document.querySelector('#smtp-test-confirm').checked`), 'SMTP page overflows, exposes a password, or preconfirms a test');
      browser.check(await browser.evaluate(`document.querySelector('#smtp-save-form').method==='post' && document.querySelector('#smtp-test-form').method==='post' && document.querySelector('#smtp-password').autocomplete==='new-password'`), 'SMTP forms lack native submission or password protection');
      await browser.evaluate(`window.smtpRequest=null;document.body.addEventListener('htmx:configRequest',e=>{window.smtpRequest={method:e.detail.verb,path:e.detail.path,fields:Array.from(e.detail.formData.entries())};e.preventDefault()})`);
      await browser.evaluate(`document.querySelector('#smtp-save').focus()`); await browser.enter();
      let request = await browser.evaluate('smtpRequest'), fields = request && Object.fromEntries(request.fields);
      browser.check(request && request.method === 'post' && request.path === base && request.fields.length === 11 && fields.settingsId === '17' && fields.revision === '10000000-0000-4000-8000-000000000001' && fields.csrf === 'owned-smtp-csrf' && fields['password-action'] === 'keep' && fields.password === '', 'SMTP save lost exact scope, review or secret preservation');
      await browser.evaluate(`smtpRequest=null;document.querySelector('#smtp-test').focus()`); await browser.enter();
      browser.check(await browser.evaluate(`smtpRequest===null && !document.querySelector('#smtp-test-form').checkValidity()`), 'SMTP test did not require explicit confirmation');
      await browser.evaluate(`document.querySelector('#smtp-test-confirm').checked=true;document.querySelector('#smtp-test').focus()`); await browser.enter();
      request = await browser.evaluate('smtpRequest'); fields = request && Object.fromEntries(request.fields);
      browser.check(request && request.path === base + '/test' && request.fields.length === 5 && fields.confirm === 'send' && fields.attempt === '10000000-0000-4000-8000-000000000003' && !('password' in fields) && !('server' in fields), 'SMTP test submitted unsaved configuration or lost its attempt identity');
      if (kind === 'normal') {
        await browser.evaluate(`smtpRequest=null;document.querySelector('#smtp-password-action').value='replace';document.querySelector('#smtp-password').value='owned-new-password';document.querySelector('#smtp-save').focus()`); await browser.enter();
        fields = Object.fromEntries((await browser.evaluate('smtpRequest')).fields);
        browser.check(fields['password-action'] === 'replace' && fields.password === 'owned-new-password', 'SMTP replacement did not submit its explicit new value');
        await browser.evaluate(`smtpRequest=null;document.querySelector('#smtp-password-action').value='clear';document.querySelector('#smtp-password').value='';document.querySelector('#smtp-save').focus()`); await browser.enter();
        fields = Object.fromEntries((await browser.evaluate('smtpRequest')).fields);
        browser.check(fields['password-action'] === 'clear' && fields.password === '', 'SMTP clearing lost its explicit action');
      }
      if (kind === 'changed') browser.check(await browser.evaluate(`document.querySelector('#smtp-last-test').textContent.includes('settings have changed')`), 'An old test appears to validate changed SMTP settings');
      if (kind === 'sent') browser.check(await browser.evaluate(`document.querySelector('#smtp-last-test').textContent.includes('Inbox delivery is not confirmed')`), 'SMTP acceptance is presented as inbox delivery');
      record({ name: 'SMTP settings ' + scope + '/' + kind, width, passed: true });
      if (width === 390 && ['normal', 'unconfirmed', 'long'].includes(kind)) await browser.capture('smtp-settings-' + scope + '-' + kind + '-390');
    }
    await browser.visit('smtp-settings-' + scope + '-normal', width);
    await browser.evaluate(`window.smtpPending=null;XMLHttpRequest.prototype.send=function(){window.smtpPending=this};document.querySelector('#smtp-save').focus()`); await browser.enter();
    browser.check(await browser.evaluate(`!!smtpPending && document.querySelector('#smtp-save').disabled && document.querySelector('#smtp-test').disabled`), 'SMTP save did not prevent concurrent actions while pending');
    await browser.evaluate(`(()=>{const xhr=smtpPending;Object.defineProperties(xhr,{status:{value:204},response:{value:''},responseText:{value:''},responseURL:{value:location.href}});xhr.getAllResponseHeaders=()=>'';xhr.getResponseHeader=()=>null;xhr.onload()})()`);
    browser.check(await browser.evaluate(`!document.querySelector('#smtp-save').disabled && !document.querySelector('#smtp-test').disabled`), 'SMTP controls did not recover after completion');
    record({ name: 'SMTP settings ' + scope + '/pending controls', width, passed: true });
  }
}
